import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import { validateCookieCandidate } from "../candidateValidator.ts";

export interface CookiesAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Specialized Audit Module: Cookies (Phase 8).
 * Inspects Set-Cookie response headers for Secure, HttpOnly, and SameSite protection flags.
 */
export function auditCookies(
  contextOrHeaders: AuditContext | Record<string, string>,
  legacyFinalUrl?: string
): CookiesAuditResult {
  const isCtx = isAuditContext(contextOrHeaders);
  const headers = isCtx ? contextOrHeaders.headers : (contextOrHeaders as Record<string, string>);
  const finalUrl = isCtx ? contextOrHeaders.finalUrl : (legacyFinalUrl || "");
  const isHttps = finalUrl.startsWith("https://");

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const setCookie = headers["set-cookie"];
  if (setCookie) {
    const cookieEval = validateCookieCandidate({
      cookieString: setCookie,
      isHttps,
    });

    if (cookieEval.outcome === "confirmed") {
      const issues = cookieEval.candidateValue?.issues || [];
      findings.push({
        id: "sec-cookie-insecure",
        category: "security",
        severity: "medium",
        priority: "fix-first",
        state: "confirmed",
        confidence: "high",
        title: "Session Cookie Security Flags Incomplete",
        description: `Set-Cookie response header was set with incomplete defense flags (${issues.join(", ")}).`,
        whyItMatters:
          "Cookies lacking HttpOnly can be accessed by injected XSS scripts. Cookies lacking Secure can leak over unencrypted networks. Cookies lacking SameSite are vulnerable to CSRF.",
        evidence: `Set-Cookie: ${setCookie.slice(0, 100)}... (${issues.join(", ")})`,
        structuredEvidence: {
          id: "ev-sec-cookie-insecure",
          sourceUrl: finalUrl,
          affectedTarget: 'response.headers["set-cookie"]',
          observation: `Set-Cookie header observed with missing flags: ${issues.join(", ")}. Raw: ${setCookie.slice(0, 100)}...`,
          expectedCondition: "Cookies specify Secure, HttpOnly, and SameSite=Lax (or Strict)",
          evidenceType: "header-inspection",
          metadata: { issues },
        },
        affectedTarget: 'response.headers["set-cookie"]',
        recommendation: "Ensure all cookies specify `Secure; HttpOnly; SameSite=Lax` (or `SameSite=Strict`).",
        codeSnippet: "Set-Cookie: session=xyz; Path=/; Secure; HttpOnly; SameSite=Lax",
      });
    } else {
      passedChecks.push({
        id: "sec-cookie-hardened",
        category: "security",
        state: "confirmed",
        confidence: "high",
        structuredEvidence: {
          id: "ev-sec-cookie-hardened",
          sourceUrl: finalUrl,
          affectedTarget: 'response.headers["set-cookie"]',
          observation: "Cookies include Secure, HttpOnly, and SameSite directives.",
          expectedCondition: "Hardened session cookie flags present",
          evidenceType: "header-inspection",
        },
        title: "Hardened Session Cookie Attributes",
        detail: "Cookies include Secure, HttpOnly, and SameSite directives.",
      });
    }
  }

  return { findings, passedChecks };
}
