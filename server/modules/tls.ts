import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";

export interface TlsAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Specialized Audit Module: TLS Observations (Phase 8).
 * Inspects transport encryption and TLS enforcement.
 */
export function auditTls(contextOrUrl: AuditContext | string): TlsAuditResult {
  const finalUrl = isAuditContext(contextOrUrl)
    ? contextOrUrl.finalUrl
    : typeof contextOrUrl === "string"
    ? contextOrUrl
    : "";

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const isHttps = finalUrl.startsWith("https://");

  if (!isHttps) {
    findings.push({
      id: "sec-insecure-http",
      category: "security",
      severity: "high",
      priority: "critical",
      state: "confirmed",
      confidence: "high",
      title: "Insecure Plaintext HTTP Protocol",
      description: "The website communicates over unencrypted HTTP rather than HTTPS.",
      whyItMatters:
        "Plaintext HTTP allows adversaries on the network path to intercept, eavesdrop on, or alter sensitive user traffic.",
      evidence: `Observed URL scheme: ${finalUrl.split(":")[0]}://`,
      structuredEvidence: {
        id: "ev-sec-insecure-http",
        sourceUrl: finalUrl,
        affectedTarget: finalUrl,
        observation: `Observed URL scheme: ${finalUrl.split(":")[0]}://`,
        expectedCondition: "Encrypted HTTPS transport protocol",
        evidenceType: "protocol-inspection",
      },
      affectedTarget: finalUrl,
      recommendation:
        "Provision a TLS certificate (e.g. Let's Encrypt) and enforce automatic HTTP-to-HTTPS 301 redirection.",
      codeSnippet: "server { listen 80; return 301 https://$host$request_uri; }",
    });
  } else {
    passedChecks.push({
      id: "sec-https-enforced",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-https-enforced",
        sourceUrl: finalUrl,
        affectedTarget: finalUrl,
        observation: "Transport negotiated securely over TLS",
        expectedCondition: "Encrypted HTTPS transport protocol",
        evidenceType: "protocol-inspection",
      },
      title: "HTTPS Transport Encryption Active",
      detail: "The site connects securely over encrypted TLS transport.",
    });
  }

  return { findings, passedChecks };
}
