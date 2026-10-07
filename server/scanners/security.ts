import { Finding, PassedCheck } from "@/types/audit";

export interface SecurityAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

export function auditSecurity(
  headers: Record<string, string>,
  finalUrl: string,
  htmlText: string
): SecurityAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const isHttps = finalUrl.startsWith("https://");

  // 1. HTTPS Check
  if (!isHttps) {
    findings.push({
      id: "sec-insecure-http",
      category: "security",
      severity: "high",
      priority: "critical",
      title: "Insecure Plaintext HTTP Protocol",
      description: "The website communicates over unencrypted HTTP rather than HTTPS.",
      whyItMatters:
        "Plaintext HTTP allows adversaries on the network path to intercept, eavesdrop on, or alter sensitive user traffic.",
      evidence: `Target URL scheme: ${finalUrl.split(":")[0]}://`,
      affectedTarget: finalUrl,
      recommendation:
        "Provision a TLS certificate (e.g. Let's Encrypt) and enforce automatic HTTP-to-HTTPS 301 redirection.",
      codeSnippet: "server { listen 80; return 301 https://$host$request_uri; }",
    });
  } else {
    passedChecks.push({
      id: "sec-https-enforced",
      category: "security",
      title: "HTTPS Transport Layer Encryption",
      detail: "The site connects securely over HTTPS.",
    });
  }

  // 2. Content-Security-Policy (CSP)
  const csp = headers["content-security-policy"];
  if (!csp) {
    findings.push({
      id: "sec-csp-missing",
      category: "security",
      severity: "high",
      priority: "critical",
      title: "Content-Security-Policy (CSP) Header Missing",
      description: "No Content-Security-Policy response header was detected.",
      whyItMatters:
        "A robust CSP acts as a defense-in-depth shield against Cross-Site Scripting (XSS), clickjacking, and unauthorized resource injection.",
      evidence: 'response.headers["content-security-policy"] → undefined',
      affectedTarget: "HTTP Response Headers",
      recommendation:
        "Define a strict Content-Security-Policy header restricting script, style, and object execution origins.",
      codeSnippet:
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
    findings.push({
      id: "sec-csp-unsafe",
      category: "security",
      severity: "medium",
      priority: "fix-first",
      title: "Overly Permissive CSP Directives Detected",
      description: "The Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval'.",
      whyItMatters:
        "Unsafe inline execution weakens protection against Cross-Site Scripting by permitting inline injected script execution.",
      evidence: `content-security-policy: ${csp.slice(0, 120)}...`,
      affectedTarget: 'response.headers["content-security-policy"]',
      recommendation:
        "Migrate inline scripts to external bundles or implement cryptographically random nonces (nonce-*) / SHA hashes.",
      codeSnippet: "script-src 'self' 'nonce-rAnd0m123'",
    });
  } else {
    passedChecks.push({
      id: "sec-csp-present",
      category: "security",
      title: "Content-Security-Policy Present",
      detail: "CSP header is configured with restricted origin controls.",
    });
  }

  // 3. Strict-Transport-Security (HSTS)
  const hsts = headers["strict-transport-security"];
  if (isHttps && !hsts) {
    findings.push({
      id: "sec-hsts-missing",
      category: "security",
      severity: "high",
      priority: "fix-first",
      title: "Strict-Transport-Security (HSTS) Missing",
      description: "HSTS header is missing on an HTTPS host.",
      whyItMatters:
        "Without HSTS, browsers may initially attempt insecure HTTP connections, exposing users to SSL-stripping and man-in-the-middle attacks.",
      evidence: 'response.headers["strict-transport-security"] → undefined',
      affectedTarget: "HTTP Response Headers",
      recommendation:
        "Add a Strict-Transport-Security header with a minimum max-age of 31536000 (1 year) and includeSubDomains.",
      codeSnippet: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    });
  } else if (isHttps && hsts) {
    passedChecks.push({
      id: "sec-hsts-present",
      category: "security",
      title: "Strict-Transport-Security (HSTS) Enforced",
      detail: `HSTS active with policy: ${hsts}`,
    });
  }

  // 4. X-Frame-Options (Clickjacking)
  const xfo = headers["x-frame-options"];
  const cspFrameAncestors = csp && csp.includes("frame-ancestors");
  if (!xfo && !cspFrameAncestors) {
    findings.push({
      id: "sec-xfo-missing",
      category: "security",
      severity: "medium",
      priority: "recommended",
      title: "Clickjacking Protection Missing",
      description: "Neither X-Frame-Options nor CSP frame-ancestors was found.",
      whyItMatters:
        "Third-party sites can embed this page inside an invisible <iframe>, tricking authenticated users into unintended actions (Clickjacking).",
      evidence:
        'response.headers["x-frame-options"] → undefined && csp["frame-ancestors"] → undefined',
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN, or specify CSP frame-ancestors 'none'.",
      codeSnippet: "X-Frame-Options: DENY",
    });
  } else {
    passedChecks.push({
      id: "sec-xfo-present",
      category: "security",
      title: "Clickjacking Protection Configured",
      detail: xfo ? `X-Frame-Options: ${xfo}` : "Protected via CSP frame-ancestors",
    });
  }

  // 5. X-Content-Type-Options
  const xcto = headers["x-content-type-options"];
  if (!xcto || !xcto.toLowerCase().includes("nosniff")) {
    findings.push({
      id: "sec-xcto-missing",
      category: "security",
      severity: "medium",
      priority: "recommended",
      title: "MIME-Type Sniffing Protection Missing",
      description: "The X-Content-Type-Options header is missing or not set to 'nosniff'.",
      whyItMatters:
        "Browsers may attempt to guess (sniff) the MIME type of a response rather than respecting Content-Type, opening execution vectors for malicious uploads.",
      evidence: `response.headers["x-content-type-options"] → ${xcto || "undefined"}`,
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set X-Content-Type-Options to 'nosniff'.",
      codeSnippet: "X-Content-Type-Options: nosniff",
    });
  } else {
    passedChecks.push({
      id: "sec-xcto-present",
      category: "security",
      title: "MIME Sniffing Blocked",
      detail: "X-Content-Type-Options is set to 'nosniff'.",
    });
  }

  // 6. Referrer-Policy
  const refPolicy = headers["referrer-policy"];
  if (!refPolicy) {
    findings.push({
      id: "sec-ref-policy-missing",
      category: "security",
      severity: "low",
      priority: "recommended",
      title: "Referrer-Policy Header Missing",
      description: "No Referrer-Policy response header was specified.",
      whyItMatters:
        "Browsers may leak sensitive internal URLs, tokens, or session IDs in the Referer header when users navigate to external links.",
      evidence: 'response.headers["referrer-policy"] → undefined',
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
      codeSnippet: "Referrer-Policy: strict-origin-when-cross-origin",
    });
  } else {
    passedChecks.push({
      id: "sec-ref-policy-present",
      category: "security",
      title: "Referrer Policy Configured",
      detail: `Referrer-Policy: ${refPolicy}`,
    });
  }

  // 7. Permissions-Policy
  const permPolicy = headers["permissions-policy"];
  if (!permPolicy) {
    findings.push({
      id: "sec-perm-policy-missing",
      category: "security",
      severity: "low",
      priority: "investigate",
      title: "Permissions-Policy Header Missing",
      description: "The modern Permissions-Policy (Feature-Policy) header is not defined.",
      whyItMatters:
        "Without Permissions-Policy, embedded iframes or scripts might request camera, microphone, geolocation, or sensor APIs without explicit domain restrictions.",
      evidence: 'response.headers["permissions-policy"] → undefined',
      affectedTarget: "HTTP Response Headers",
      recommendation: "Restrict unused browser hardware features with Permissions-Policy.",
      codeSnippet: "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    });
  } else {
    passedChecks.push({
      id: "sec-perm-policy-present",
      category: "security",
      title: "Browser Permissions-Policy Configured",
      detail: "Permissions-Policy limits sensitive browser API execution.",
    });
  }

  // 8. Server Banner Information Disclosure
  const serverHeader = headers["server"];
  if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
    findings.push({
      id: "sec-server-version-leak",
      category: "security",
      severity: "low",
      priority: "investigate",
      title: "Server Software Version Disclosed",
      description: `The Server response header discloses specific daemon software version information (${serverHeader}).`,
      whyItMatters:
        "Publicly broadcasting specific daemon version numbers assists attackers in cross-referencing known CVE vulnerability databases.",
      evidence: `Server: ${serverHeader}`,
      affectedTarget: 'response.headers["server"]',
      recommendation:
        "Configure your reverse proxy or web server (e.g. nginx `server_tokens off;` or apache `ServerTokens Prod`) to suppress version strings.",
      codeSnippet: "server_tokens off;",
    });
  }

  // 9. X-Powered-By Disclosure
  const poweredBy = headers["x-powered-by"];
  if (poweredBy) {
    findings.push({
      id: "sec-powered-by-leak",
      category: "security",
      severity: "low",
      priority: "investigate",
      title: "Backend Technology Fingerprint Disclosed",
      description: `The X-Powered-By header discloses underlying application framework (${poweredBy}).`,
      whyItMatters:
        "Broadcasting backend technologies narrows reconnaissance options for adversaries searching for framework-specific exploits.",
      evidence: `X-Powered-By: ${poweredBy}`,
      affectedTarget: 'response.headers["x-powered-by"]',
      recommendation: "Disable the X-Powered-By header in your application framework settings.",
      codeSnippet: "app.disable('x-powered-by'); // Express.js\n// or poweredByHeader: false in next.config",
    });
  }

  // 10. Mixed Content Check (if HTTPS)
  if (isHttps) {
    const insecureSources = htmlText.match(/src=["']http:\/\/[^"']+/gi) || [];
    if (insecureSources.length > 0) {
      findings.push({
        id: "sec-mixed-content",
        category: "security",
        severity: "high",
        priority: "critical",
        title: "Insecure Mixed Content Subresources Detected",
        description: `Found ${insecureSources.length} resources loaded over unencrypted HTTP on an HTTPS page.`,
        whyItMatters:
          "Modern browsers will block mixed active content (scripts, stylesheets) and warn users about mixed passive content, breaking functionality.",
        evidence: `Sample insecure resource: ${insecureSources[0]?.slice(0, 80) || ""}`,
        affectedTarget: "HTML Source Assets",
        recommendation: "Update all asset references to use HTTPS or protocol-relative schemes.",
        codeSnippet: '<script src="https://..."></script>',
        instancesCount: insecureSources.length,
        instances: insecureSources.slice(0, 5),
      });
    }
  }

  return { findings, passedChecks };
}
