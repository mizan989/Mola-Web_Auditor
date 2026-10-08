import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import { auditHttpInfrastructure } from "../modules/httpInfrastructure.ts";
import { auditTls } from "../modules/tls.ts";
import { auditSecurityHeaders } from "../modules/securityHeaders.ts";
import { auditMixedContent } from "../modules/mixedContent.ts";

export interface SecurityAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Audits HTTP response security headers and document-level security posture.
 * Composes specialized audit modules (Phase 8): TLS observations, Security Headers, and Mixed Content.
 * Consumes the shared authoritative AuditContext (Phase 2), with fallback to direct parameters.
 */
export function auditSecurity(
  contextOrHeaders: AuditContext | Record<string, string>,
  legacyFinalUrl?: string,
  legacyHtmlText?: string
): SecurityAuditResult {
  const isCtx = isAuditContext(contextOrHeaders);
  const context = isCtx ? contextOrHeaders : undefined;
  const headers = isCtx ? contextOrHeaders.headers : (contextOrHeaders as Record<string, string>);
  const finalUrl = isCtx ? contextOrHeaders.finalUrl : (legacyFinalUrl || "");
  const htmlText = isCtx ? contextOrHeaders.body.text : (legacyHtmlText || "");

  // If connection failed completely with zero status code, return unable_to_check finding
  if (context?.metadata?.isPartial && context.response.statusCode === 0) {
    const infra = auditHttpInfrastructure(context);
    return {
      findings: infra.findings.filter((f) => f.category === "security"),
      passedChecks: infra.passedChecks.filter((c) => c.category === "security"),
    };
  }

  const tls = auditTls(finalUrl);
  const secHeaders = auditSecurityHeaders(headers, finalUrl);
  const mixed = auditMixedContent({ isHttps: finalUrl.startsWith("https://"), finalUrl, htmlText });

  return {
    findings: [...tls.findings, ...secHeaders.findings, ...mixed.findings],
    passedChecks: [...tls.passedChecks, ...secHeaders.passedChecks, ...mixed.passedChecks],
  };
}
