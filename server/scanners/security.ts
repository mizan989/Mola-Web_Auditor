import { Finding, PassedCheck } from "@/types/audit";

export interface SecurityAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Audits HTTP response security headers and document-level security posture.
 * Complies with ISSUE-018 (clear separation of headers vs document checks)
 * and ISSUE-019 (precise subresource mixed content verification on HTTPS pages).
 */
export function auditSecurity(
  headers: Record<string, string>,
  finalUrl: string,
  htmlText: string
): SecurityAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const isHttps = finalUrl.startsWith("https://");

  // ==========================================
  // SECTION 1: Transport Layer Security (TLS)
  // ==========================================
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
      evidence: `Observed URL scheme: ${finalUrl.split(":")[0]}://`,
      affectedTarget: finalUrl,
      recommendation:
        "Provision a TLS certificate (e.g. Let's Encrypt) and enforce automatic HTTP-to-HTTPS 301 redirection.",
      codeSnippet: "server { listen 80; return 301 https://$host$request_uri; }",
    });
  } else {
    passedChecks.push({
      id: "sec-https-enforced",
      category: "security",
      title: "HTTPS Transport Encryption Active",
      detail: "The site connects securely over encrypted TLS transport.",
    });
  }

  // ==========================================
  // SECTION 2: HTTP Response Security Headers
  // ==========================================

  // 1. Content-Security-Policy (CSP)
  const csp = headers["content-security-policy"];
  if (!csp) {
    findings.push({
      id: "sec-csp-missing",
      category: "security",
      severity: "high",
      priority: "critical",
      title: "Content-Security-Policy (CSP) Header Missing",
      description: "No Content-Security-Policy response header was detected in the HTTP headers.",
      whyItMatters:
        "A robust CSP acts as a defense-in-depth shield against Cross-Site Scripting (XSS), clickjacking, and unauthorized resource injection.",
      evidence: 'response.headers["content-security-policy"] is undefined',
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
      evidence: `content-security-policy: ${csp.slice(0, 140)}...`,
      affectedTarget: 'response.headers["content-security-policy"]',
      recommendation:
        "Migrate inline scripts to external bundles or implement cryptographically random nonces (nonce-*) / SHA hashes.",
      codeSnippet: "script-src 'self' 'nonce-rAnd0m123'",
    });
  } else {
    passedChecks.push({
      id: "sec-csp-present",
      category: "security",
      title: "Content-Security-Policy Configured",
      detail: "CSP header is configured with restricted origin controls.",
    });
  }

  // 2. Strict-Transport-Security (HSTS)
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
      evidence: 'response.headers["strict-transport-security"] is undefined',
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

  // 3. X-Frame-Options (Clickjacking)
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
        'response.headers["x-frame-options"] is undefined and CSP frame-ancestors is undefined',
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN, or specify CSP frame-ancestors 'none'.",
      codeSnippet: "X-Frame-Options: DENY",
    });
  } else {
    passedChecks.push({
      id: "sec-xfo-present",
      category: "security",
      title: "Clickjacking Protection Configured",
      detail: xfo ? `X-Frame-Options: ${xfo}` : "Protected via CSP frame-ancestors directive",
    });
  }

  // 4. X-Content-Type-Options
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

  // 5. Referrer-Policy
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
      evidence: 'response.headers["referrer-policy"] is undefined',
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

  // 6. Permissions-Policy
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
      evidence: 'response.headers["permissions-policy"] is undefined',
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

  // 7. Server Banner Information Disclosure
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

  // 8. X-Powered-By Disclosure
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

  // ==========================================
  // SECTION 3: Document Content Security Checks
  // ==========================================

  // 9. Mixed Content Verification (ISSUE-019)
  if (isHttps) {
    const mixedPatterns = [
      /<script\b[^>]*\bsrc=["'](http:\/\/[^"']+)["']/gi,
      /<link\b[^>]*\bhref=["'](http:\/\/[^"']+)["']/gi,
      /<img\b[^>]*\bsrc=["'](http:\/\/[^"']+)["']/gi,
      /<iframe\b[^>]*\bsrc=["'](http:\/\/[^"']+)["']/gi,
      /<(?:video|audio|source)\b[^>]*\bsrc=["'](http:\/\/[^"']+)["']/gi,
    ];
    const insecureSources: string[] = [];

    for (const pattern of mixedPatterns) {
      const matches = htmlText.matchAll(pattern);
      for (const m of matches) {
        if (m[1] && !insecureSources.includes(m[1])) {
          insecureSources.push(m[1]);
        }
      }
    }

    if (insecureSources.length > 0) {
      findings.push({
        id: "sec-mixed-content",
        category: "security",
        severity: "high",
        priority: "critical",
        title: "Insecure Mixed Content Subresources Detected",
        description: `Found ${insecureSources.length} subresource(s) loaded over unencrypted HTTP on an HTTPS page.`,
        whyItMatters:
          "Modern browsers will block mixed active content (scripts, stylesheets) and display security warnings for mixed passive content, breaking site functionality.",
        evidence: `Sample insecure subresource: ${insecureSources[0]}`,
        affectedTarget: "HTML Subresources",
        recommendation: "Update all subresource URLs to use HTTPS or relative paths.",
        codeSnippet: '<script src="https://example.com/bundle.js"></script>',
        instancesCount: insecureSources.length,
        instances: insecureSources.slice(0, 5),
      });
    } else {
      passedChecks.push({
        id: "sec-mixed-content-clean",
        category: "security",
        title: "Zero Mixed Content Detected",
        detail: "All inspected subresources (scripts, styles, images) load securely over HTTPS.",
      });
    }
  }

  return { findings, passedChecks };
}
