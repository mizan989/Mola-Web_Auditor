import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import {
  validateHstsCandidate,
  validateCspUnsafeCandidate,
  validateXfoCandidate,
} from "../candidateValidator.ts";

export interface SecurityHeadersAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Specialized Audit Module: Security Headers (Phase 8).
 * Evaluates HTTP response security headers: CSP, HSTS, XFO, XCTO,
 * Referrer-Policy, Permissions-Policy, Server banner, and X-Powered-By.
 */
export function auditSecurityHeaders(
  contextOrHeaders: AuditContext | Record<string, string>,
  legacyFinalUrl?: string
): SecurityHeadersAuditResult {
  const isCtx = isAuditContext(contextOrHeaders);
  const headers = isCtx ? contextOrHeaders.headers : (contextOrHeaders as Record<string, string>);
  const finalUrl = isCtx ? contextOrHeaders.finalUrl : (legacyFinalUrl || "");
  const isHttps = finalUrl.startsWith("https://");

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. Content-Security-Policy (CSP)
  const csp = headers["content-security-policy"];
  if (!csp) {
    findings.push({
      id: "sec-csp-missing",
      category: "security",
      severity: "high",
      priority: "critical",
      state: "confirmed",
      confidence: "high",
      title: "Content-Security-Policy (CSP) Header Missing",
      description: "No Content-Security-Policy response header was detected in the HTTP headers.",
      whyItMatters:
        "A robust CSP acts as a defense-in-depth shield against Cross-Site Scripting (XSS), clickjacking, and unauthorized resource injection.",
      evidence: 'response.headers["content-security-policy"] is undefined',
      structuredEvidence: {
        id: "ev-sec-csp-missing",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: 'response.headers["content-security-policy"] is undefined',
        expectedCondition: "Content-Security-Policy header defined with restrictive origin controls",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation:
        "Define a strict Content-Security-Policy header restricting script, style, and object execution origins.",
      codeSnippet:
        "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
    });
  } else {
    const scriptSrcMatch = csp.match(/(?:^|;)\s*script-src\s+([^;]+)/i);
    const defaultSrcMatch = csp.match(/(?:^|;)\s*default-src\s+([^;]+)/i);
    const scriptDirective = (scriptSrcMatch ? scriptSrcMatch[1] : (defaultSrcMatch ? defaultSrcMatch[1] : "")).trim();

    const hasUnsafeEval = scriptDirective.includes("'unsafe-eval'");
    const cspUnsafeEval = validateCspUnsafeCandidate({ cspHeader: csp });

    if (hasUnsafeEval || cspUnsafeEval.outcome === "confirmed") {
      findings.push({
        id: "sec-csp-unsafe",
        category: "security",
        severity: "medium",
        priority: "fix-first",
        state: "confirmed",
        confidence: "high",
        title: "Overly Permissive CSP Directives Detected",
        description: hasUnsafeEval
          ? "The Content-Security-Policy header permits 'unsafe-eval', allowing dynamic code evaluation."
          : "The Content-Security-Policy header permits un-nonced 'unsafe-inline' scripts, weakening XSS mitigation.",
        whyItMatters:
          "Unsafe script execution weakens protection against Cross-Site Scripting by permitting dynamic evaluation or injected script execution.",
        evidence: `content-security-policy: ${csp.slice(0, 140)}...`,
        structuredEvidence: {
          id: "ev-sec-csp-unsafe",
          sourceUrl: finalUrl,
          affectedTarget: 'response.headers["content-security-policy"]',
          observation: `content-security-policy: ${csp.slice(0, 140)}...`,
          expectedCondition: "No un-nonced 'unsafe-inline' or 'unsafe-eval' script directives",
          evidenceType: "header-inspection",
        },
        affectedTarget: 'response.headers["content-security-policy"]',
        recommendation:
          "Migrate inline scripts to external bundles or implement cryptographically random nonces (nonce-*) / SHA hashes.",
        codeSnippet: "script-src 'self' 'nonce-rAnd0m123'",
      });
    } else {
      passedChecks.push({
        id: "sec-csp-present",
        category: "security",
        state: "confirmed",
        confidence: "high",
        structuredEvidence: {
          id: "ev-sec-csp-present",
          sourceUrl: finalUrl,
          affectedTarget: 'response.headers["content-security-policy"]',
          observation: "CSP header is configured with restricted origin controls",
          expectedCondition: "Restricted script and execution origins",
          evidenceType: "header-inspection",
        },
        title: "Content-Security-Policy Configured",
        detail: "CSP header is configured with restricted origin controls.",
      });
    }
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = headers["strict-transport-security"];
  const hstsEval = validateHstsCandidate({ isHttps, hstsHeader: hsts });
  if (hstsEval.outcome === "confirmed") {
    findings.push({
      id: "sec-hsts-missing",
      category: "security",
      severity: "high",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Strict-Transport-Security (HSTS) Missing",
      description: "HSTS header is missing on an HTTPS host.",
      whyItMatters:
        "Without HSTS, browsers may initially attempt insecure HTTP connections, exposing users to SSL-stripping and man-in-the-middle attacks.",
      evidence: 'response.headers["strict-transport-security"] is undefined',
      structuredEvidence: {
        id: "ev-sec-hsts-missing",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: 'response.headers["strict-transport-security"] is undefined',
        expectedCondition: "Strict-Transport-Security header present on HTTPS host with min max-age 31536000",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation:
        "Add a Strict-Transport-Security header with a minimum max-age of 31536000 (1 year) and includeSubDomains.",
      codeSnippet: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    });
  } else if (isHttps && hsts) {
    passedChecks.push({
      id: "sec-hsts-present",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-hsts-present",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: `HSTS active with policy: ${hsts}`,
        expectedCondition: "Strict-Transport-Security header configured",
        evidenceType: "header-inspection",
      },
      title: "Strict-Transport-Security (HSTS) Enforced",
      detail: `HSTS active with policy: ${hsts}`,
    });
  }

  // 3. X-Frame-Options (Clickjacking)
  const xfo = headers["x-frame-options"];
  const xfoEval = validateXfoCandidate({ xfoHeader: xfo, cspHeader: csp });
  if (xfoEval.outcome === "confirmed") {
    findings.push({
      id: "sec-xfo-missing",
      category: "security",
      severity: "medium",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Clickjacking Protection Missing",
      description: "Neither X-Frame-Options nor CSP frame-ancestors was found.",
      whyItMatters:
        "Third-party sites can embed this page inside an invisible <iframe>, tricking authenticated users into unintended actions (Clickjacking).",
      evidence:
        'response.headers["x-frame-options"] is undefined and CSP frame-ancestors is undefined',
      structuredEvidence: {
        id: "ev-sec-xfo-missing",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: 'response.headers["x-frame-options"] is undefined and CSP frame-ancestors is undefined',
        expectedCondition: "X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors defined",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN, or specify CSP frame-ancestors 'none'.",
      codeSnippet: "X-Frame-Options: DENY",
    });
  } else {
    passedChecks.push({
      id: "sec-xfo-present",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-xfo-present",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: xfo ? `X-Frame-Options: ${xfo}` : "Protected via CSP frame-ancestors directive",
        expectedCondition: "Framing protections active",
        evidenceType: "header-inspection",
      },
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
      state: "confirmed",
      confidence: "high",
      title: "MIME-Type Sniffing Protection Missing",
      description: "The X-Content-Type-Options header is missing or not set to 'nosniff'.",
      whyItMatters:
        "Browsers may attempt to guess (sniff) the MIME type of a response rather than respecting Content-Type, opening execution vectors for malicious uploads.",
      evidence: `response.headers["x-content-type-options"] → ${xcto || "undefined"}`,
      structuredEvidence: {
        id: "ev-sec-xcto-missing",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: `response.headers["x-content-type-options"] -> ${xcto || "undefined"}`,
        expectedCondition: "X-Content-Type-Options: nosniff",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set X-Content-Type-Options to 'nosniff'.",
      codeSnippet: "X-Content-Type-Options: nosniff",
    });
  } else {
    passedChecks.push({
      id: "sec-xcto-present",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-xcto-present",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: "X-Content-Type-Options is set to 'nosniff'",
        expectedCondition: "X-Content-Type-Options: nosniff",
        evidenceType: "header-inspection",
      },
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
      state: "confirmed",
      confidence: "high",
      title: "Referrer-Policy Header Missing",
      description: "No Referrer-Policy response header was specified.",
      whyItMatters:
        "Browsers may leak sensitive internal URLs, tokens, or session IDs in the Referer header when users navigate to external links.",
      evidence: 'response.headers["referrer-policy"] is undefined',
      structuredEvidence: {
        id: "ev-sec-ref-policy-missing",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: 'response.headers["referrer-policy"] is undefined',
        expectedCondition: "Referrer-Policy header specified",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation: "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
      codeSnippet: "Referrer-Policy: strict-origin-when-cross-origin",
    });
  } else {
    passedChecks.push({
      id: "sec-ref-policy-present",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-ref-policy-present",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: `Referrer-Policy: ${refPolicy}`,
        expectedCondition: "Referrer-Policy header present",
        evidenceType: "header-inspection",
      },
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
      state: "recommendation",
      confidence: "high",
      title: "Permissions-Policy Header Missing",
      description: "The modern Permissions-Policy (Feature-Policy) header is not defined.",
      whyItMatters:
        "Without Permissions-Policy, embedded iframes or scripts might request camera, microphone, geolocation, or sensor APIs without explicit domain restrictions.",
      evidence: 'response.headers["permissions-policy"] is undefined',
      structuredEvidence: {
        id: "ev-sec-perm-policy-missing",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: 'response.headers["permissions-policy"] is undefined',
        expectedCondition: "Permissions-Policy header defined restricting unused APIs",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation: "Restrict unused browser hardware features with Permissions-Policy.",
      codeSnippet: "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    });
  } else {
    passedChecks.push({
      id: "sec-perm-policy-present",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-perm-policy-present",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Headers",
        observation: "Permissions-Policy limits sensitive browser API execution",
        expectedCondition: "Permissions-Policy defined",
        evidenceType: "header-inspection",
      },
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
      state: "observation",
      confidence: "high",
      title: "Server Software Version Disclosed",
      description: `The Server response header discloses specific daemon software version information (${serverHeader}).`,
      whyItMatters:
        "Publicly broadcasting specific daemon version numbers assists attackers in cross-referencing known CVE vulnerability databases.",
      evidence: `Server: ${serverHeader}`,
      structuredEvidence: {
        id: "ev-sec-server-version-leak",
        sourceUrl: finalUrl,
        affectedTarget: 'response.headers["server"]',
        observation: `Server: ${serverHeader}`,
        expectedCondition: "Generic server banner without exact version numbers",
        evidenceType: "header-inspection",
      },
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
      state: "observation",
      confidence: "high",
      title: "Backend Technology Fingerprint Disclosed",
      description: `The X-Powered-By header discloses underlying application framework (${poweredBy}).`,
      whyItMatters:
        "Broadcasting backend technologies narrows reconnaissance options for adversaries searching for framework-specific exploits.",
      evidence: `X-Powered-By: ${poweredBy}`,
      structuredEvidence: {
        id: "ev-sec-powered-by-leak",
        sourceUrl: finalUrl,
        affectedTarget: 'response.headers["x-powered-by"]',
        observation: `X-Powered-By: ${poweredBy}`,
        expectedCondition: "X-Powered-By header suppressed or absent",
        evidenceType: "header-inspection",
      },
      affectedTarget: 'response.headers["x-powered-by"]',
      recommendation: "Disable the X-Powered-By header in your application framework settings.",
      codeSnippet: "app.disable('x-powered-by'); // Express.js\n// or poweredByHeader: false in next.config",
    });
  }

  return { findings, passedChecks };
}
