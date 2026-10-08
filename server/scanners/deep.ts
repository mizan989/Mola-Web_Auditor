import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import { auditResourceIntegrity } from "../modules/resourceIntegrity.ts";
import { auditCookies } from "../modules/cookies.ts";
import { auditIframeSafety } from "../modules/iframeSafety.ts";

export interface DeepScanResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Performs deep resource, third-party script, and subresource security inspection.
 * Composes specialized audit modules (Phase 8): Resource Integrity (SRI), Cookies, and Iframe Safety.
 * Consumes the shared authoritative AuditContext (Phase 2), with fallback to direct parameters.
 */
export function auditDeepScan(
  contextOrHeaders: AuditContext | Record<string, string>,
  legacyFinalUrl?: string,
  legacyHtmlText?: string
): DeepScanResult {
  const isCtx = isAuditContext(contextOrHeaders);
  const headers = isCtx ? contextOrHeaders.headers : (contextOrHeaders as Record<string, string>);
  const finalUrl = isCtx ? contextOrHeaders.finalUrl : (legacyFinalUrl || "");
  const htmlText = isCtx ? contextOrHeaders.body.text : (legacyHtmlText || "");

  // 1. Third-Party Script Subresource Integrity (SRI) Audit
  const sri = auditResourceIntegrity({ finalUrl, htmlText });

  // 2. Cookie Security Attributes (Set-Cookie)
  const cookies = auditCookies(headers, finalUrl);

  // 3. Iframe Sandbox & Lazy Loading
  const iframes = auditIframeSafety({ finalUrl, htmlText });

  return {
    findings: [...sri.findings, ...cookies.findings, ...iframes.findings],
    passedChecks: [...sri.passedChecks, ...cookies.passedChecks, ...iframes.passedChecks],
  };
}
