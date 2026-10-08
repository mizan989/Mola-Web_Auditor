import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import { parseHtmlDocument, extractInsecureMixedContent } from "../htmlParser.ts";
import { validateMixedContentCandidate } from "../candidateValidator.ts";

export interface MixedContentAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Specialized Audit Module: Mixed Content (Phase 8).
 * Inspects parsed DOM on HTTPS hosts to detect insecure subresources (scripts,
 * stylesheets, images, iframes) loaded over plaintext HTTP.
 */
export function auditMixedContent(
  contextOrOptions: AuditContext | { isHttps?: boolean; finalUrl?: string; htmlText?: string },
  legacyFinalUrl?: string,
  legacyHtmlText?: string
): MixedContentAuditResult {
  let isHttps: boolean;
  let finalUrl: string;
  let htmlText: string;

  if (isAuditContext(contextOrOptions)) {
    finalUrl = contextOrOptions.finalUrl;
    htmlText = contextOrOptions.body.text;
    isHttps = contextOrOptions.finalUrl.startsWith("https://");
  } else if (typeof contextOrOptions === "object" && "htmlText" in contextOrOptions) {
    finalUrl = contextOrOptions.finalUrl || "";
    htmlText = contextOrOptions.htmlText || "";
    isHttps = contextOrOptions.isHttps !== undefined ? contextOrOptions.isHttps : finalUrl.startsWith("https://");
  } else {
    finalUrl = legacyFinalUrl || "";
    htmlText = legacyHtmlText || "";
    isHttps = finalUrl.startsWith("https://");
  }

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  if (!isHttps) {
    // Mixed content is only applicable to HTTPS pages.
    return { findings, passedChecks };
  }

  const root = parseHtmlDocument(htmlText);
  const candidateSources = extractInsecureMixedContent(root);
  const insecureSources: string[] = [];

  for (const src of candidateSources) {
    const evaluation = validateMixedContentCandidate({ url: src, isHttps });
    if (evaluation.outcome === "confirmed") {
      insecureSources.push(src);
    }
  }

  if (insecureSources.length > 0) {
    findings.push({
      id: "sec-mixed-content",
      category: "security",
      severity: "high",
      priority: "critical",
      state: "confirmed",
      confidence: "high",
      title: "Insecure Mixed Content Subresources Detected",
      description: `Found ${insecureSources.length} subresource(s) loaded over unencrypted HTTP on an HTTPS page.`,
      whyItMatters:
        "Modern browsers will block mixed active content (scripts, stylesheets) and display security warnings for mixed passive content, breaking site functionality.",
      evidence: `Sample insecure subresource: ${insecureSources[0]}`,
      structuredEvidence: {
        id: "ev-sec-mixed-content",
        sourceUrl: finalUrl,
        affectedTarget: "HTML Subresources",
        observation: `Sample insecure subresource: ${insecureSources[0]}`,
        expectedCondition: "All subresources requested over HTTPS",
        evidenceType: "subresource-dom-inspection",
        metadata: {
          insecureCount: insecureSources.length,
          sampleSources: insecureSources.slice(0, 5),
        },
      },
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
      state: "not_detected",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-mixed-content-clean",
        sourceUrl: finalUrl,
        affectedTarget: "HTML Subresources",
        observation: "Zero unencrypted HTTP subresources detected",
        expectedCondition: "Zero mixed content subresources",
        evidenceType: "subresource-dom-inspection",
      },
      title: "Zero Mixed Content Detected",
      detail: "All inspected subresources (scripts, styles, images) load securely over HTTPS.",
    });
  }

  return { findings, passedChecks };
}
