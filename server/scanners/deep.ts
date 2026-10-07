import type { Finding, PassedCheck } from "../../types/audit.ts";

export interface DeepScanResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Performs deep resource, third-party script, and subresource security inspection.
 * Executed exclusively during Deep Scan mode (Complies with ISSUE-009, ISSUE-022, ISSUE-023).
 */
export function auditDeepScan(
  headers: Record<string, string>,
  finalUrl: string,
  htmlText: string
): DeepScanResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const host = new URL(finalUrl).hostname;

  // 1. Third-Party Script Subresource Integrity (SRI) Audit
  const scriptTags = Array.from(htmlText.matchAll(/<script\b([^>]*)>/gi));
  const externalScriptsWithoutSri: string[] = [];
  let totalExternalScripts = 0;

  for (const match of scriptTags) {
    const attrs = match[1];
    const srcMatch = attrs.match(/\bsrc=["']([^"']+)["']/i);
    if (!srcMatch) continue;

    const src = srcMatch[1];
    // Check if script is hosted on external domain
    if (src.startsWith("//") || src.startsWith("http://") || src.startsWith("https://")) {
      try {
        const scriptHost = new URL(src, finalUrl).hostname;
        if (scriptHost !== host) {
          totalExternalScripts++;
          const hasIntegrity = /\bintegrity=["']sha(?:256|384|512)-/i.test(attrs);
          if (!hasIntegrity) {
            externalScriptsWithoutSri.push(src);
          }
        }
      } catch {
        // Ignore unparseable URLs
      }
    }
  }

  if (externalScriptsWithoutSri.length > 0) {
    findings.push({
      id: "sec-sri-missing",
      category: "security",
      severity: "medium",
      priority: "fix-first",
      title: "Third-Party Scripts Missing Subresource Integrity (SRI)",
      description: `Detected ${externalScriptsWithoutSri.length} external script(s) loaded from third-party domains without cryptographic 'integrity' hashes.`,
      whyItMatters:
        "If a third-party CDN or external host is compromised, adversaries can tamper with script assets and execute malicious code in your users' browsers without SRI verification.",
      evidence: `Sample external script without SRI: ${externalScriptsWithoutSri[0]}`,
      affectedTarget: "<script> tags",
      recommendation:
        "Add cryptographic sha384 or sha512 integrity hashes and crossorigin=\"anonymous\" attributes to all external scripts.",
      codeSnippet:
        '<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-..."\n  crossorigin="anonymous"></script>',
      instancesCount: externalScriptsWithoutSri.length,
      instances: externalScriptsWithoutSri.slice(0, 5),
    });
  } else if (totalExternalScripts > 0) {
    passedChecks.push({
      id: "sec-sri-verified",
      category: "security",
      title: "Subresource Integrity (SRI) Enforced",
      detail: `All ${totalExternalScripts} external third-party scripts include cryptographic integrity hashes.`,
    });
  }

  // 2. Cookie Security Attributes (Set-Cookie)
  const setCookie = headers["set-cookie"];
  if (setCookie) {
    const isSecure = /\bsecure\b/i.test(setCookie);
    const isHttpOnly = /\bhttponly\b/i.test(setCookie);
    const hasSameSite = /\bsamesite=(?:lax|strict|none)\b/i.test(setCookie);

    const issues: string[] = [];
    if (!isSecure && finalUrl.startsWith("https://")) issues.push("missing 'Secure' flag");
    if (!isHttpOnly) issues.push("missing 'HttpOnly' flag");
    if (!hasSameSite) issues.push("missing 'SameSite' attribute");

    if (issues.length > 0) {
      findings.push({
        id: "sec-cookie-insecure",
        category: "security",
        severity: "medium",
        priority: "fix-first",
        title: "Session Cookie Security Flags Incomplete",
        description: `Set-Cookie response header was set with incomplete defense flags (${issues.join(", ")}).`,
        whyItMatters:
          "Cookies lacking HttpOnly can be accessed by injected XSS scripts. Cookies lacking Secure can leak over unencrypted networks. Cookies lacking SameSite are vulnerable to CSRF.",
        evidence: `Set-Cookie: ${setCookie.slice(0, 100)}... (${issues.join(", ")})`,
        affectedTarget: 'response.headers["set-cookie"]',
        recommendation: "Ensure all cookies specify `Secure; HttpOnly; SameSite=Lax` (or `SameSite=Strict`).",
        codeSnippet: "Set-Cookie: session=xyz; Path=/; Secure; HttpOnly; SameSite=Lax",
      });
    } else {
      passedChecks.push({
        id: "sec-cookie-hardened",
        category: "security",
        title: "Hardened Session Cookie Attributes",
        detail: "Cookies include Secure, HttpOnly, and SameSite directives.",
      });
    }
  }

  // 3. Iframe Sandbox & Lazy Loading
  const iframeTags = Array.from(htmlText.matchAll(/<iframe\b([^>]*)>/gi));
  const iframesMissingSandbox: string[] = [];
  const iframesMissingLazy: string[] = [];

  for (const match of iframeTags) {
    const attrs = match[1];
    const srcMatch = attrs.match(/\bsrc=["']([^"']+)["']/i);
    const src = srcMatch ? srcMatch[1] : "unknown-iframe";

    if (!/\bsandbox\b/i.test(attrs)) {
      iframesMissingSandbox.push(src);
    }
    if (!/\bloading=["']lazy["']/i.test(attrs)) {
      iframesMissingLazy.push(src);
    }
  }

  if (iframesMissingSandbox.length > 0) {
    findings.push({
      id: "sec-iframe-sandbox-missing",
      category: "security",
      severity: "low",
      priority: "investigate",
      title: "Embedded <iframe> Missing Sandbox Restrictions",
      description: `Detected ${iframesMissingSandbox.length} iframe element(s) without a 'sandbox' attribute.`,
      whyItMatters:
        "An un-sandboxed iframe can execute top-level navigation, run arbitrary scripts, or display phishing overlays.",
      evidence: `Sample iframe: ${iframesMissingSandbox[0]}`,
      affectedTarget: "HTML <iframe> Elements",
      recommendation: "Add `sandbox=\"allow-scripts allow-same-origin\"` (or more restrictive) to embedded frames.",
      codeSnippet: '<iframe src="..." sandbox="allow-scripts" loading="lazy"></iframe>',
      instancesCount: iframesMissingSandbox.length,
      instances: iframesMissingSandbox.slice(0, 4),
    });
  }

  if (iframesMissingLazy.length > 0) {
    findings.push({
      id: "perf-iframe-lazy-missing",
      category: "performance",
      severity: "low",
      priority: "recommended",
      title: "Embedded <iframe> Missing Lazy Loading",
      description: `${iframesMissingLazy.length} embedded iframe(s) do not use \`loading="lazy"\`.`,
      whyItMatters:
        "Non-lazy iframes eagerly download third-party embeds (videos, widgets) during initial page load, consuming bandwidth and CPU.",
      evidence: `Sample iframe: ${iframesMissingLazy[0]}`,
      affectedTarget: "HTML <iframe> Elements",
      recommendation: "Add `loading=\"lazy\"` to off-screen iframe embeds.",
      codeSnippet: '<iframe src="..." loading="lazy"></iframe>',
      instancesCount: iframesMissingLazy.length,
    });
  }

  // 4. Headless Rendered Environment Note (ISSUE-022)
  passedChecks.push({
    id: "deep-resource-inspection-complete",
    category: "best-practices",
    title: "Deep Subresource & Asset Audit",
    detail: `Inspected ${scriptTags.length} script tags, ${iframeTags.length} iframes, and subresource security policies. (Headless browser rendering is not configured in this serverless environment; static resource tree inspected).`,
  });

  return { findings, passedChecks };
}
