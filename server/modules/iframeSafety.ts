import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import { parseHtmlDocument, extractIframes } from "../htmlParser.ts";
import { validateIframeSecurityCandidate } from "../candidateValidator.ts";

export interface IframeSafetyAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Specialized Audit Module: Iframe & Resource Safety (Phase 8).
 * Inspects embedded <iframe> elements for sandbox security attributes and loading='lazy'.
 */
export function auditIframeSafety(
  contextOrOptions: AuditContext | { finalUrl: string; htmlText: string },
  legacyHtmlText?: string
): IframeSafetyAuditResult {
  let finalUrl: string;
  let htmlText: string;

  if (isAuditContext(contextOrOptions)) {
    finalUrl = contextOrOptions.finalUrl;
    htmlText = contextOrOptions.body.text;
  } else if (typeof contextOrOptions === "object" && "htmlText" in contextOrOptions) {
    finalUrl = contextOrOptions.finalUrl;
    htmlText = contextOrOptions.htmlText;
  } else {
    finalUrl = typeof contextOrOptions === "string" ? contextOrOptions : "";
    htmlText = legacyHtmlText || "";
  }

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const root = parseHtmlDocument(htmlText);
  const iframes = extractIframes(root);
  const iframesMissingSandbox: string[] = [];
  const iframesMissingLazy: string[] = [];

  for (const iframe of iframes) {
    const { sandboxEvaluation, lazyEvaluation } = validateIframeSecurityCandidate({
      src: iframe.src,
      hasSandbox: iframe.hasSandbox,
      isLazy: iframe.isLazy,
    });

    if (sandboxEvaluation.outcome === "confirmed") {
      iframesMissingSandbox.push(iframe.src);
    }
    if (lazyEvaluation.outcome === "confirmed") {
      iframesMissingLazy.push(iframe.src);
    }
  }

  if (iframesMissingSandbox.length > 0) {
    findings.push({
      id: "sec-iframe-sandbox-missing",
      category: "security",
      severity: "low",
      priority: "investigate",
      state: "confirmed",
      confidence: "high",
      title: "Embedded <iframe> Missing Sandbox Restrictions",
      description: `Detected ${iframesMissingSandbox.length} iframe element(s) without a 'sandbox' attribute.`,
      whyItMatters:
        "An un-sandboxed iframe can execute top-level navigation, run arbitrary scripts, or display phishing overlays.",
      evidence: `Sample iframe: ${iframesMissingSandbox[0]}`,
      structuredEvidence: {
        id: "ev-sec-iframe-sandbox-missing",
        sourceUrl: finalUrl,
        affectedTarget: iframesMissingSandbox[0],
        observation: `Detected ${iframesMissingSandbox.length} iframe element(s) without a sandbox attribute. Sample: ${iframesMissingSandbox[0]}`,
        expectedCondition: "Embedded iframes specify a restrictive sandbox attribute",
        evidenceType: "html-iframe-inspection",
        metadata: {
          count: iframesMissingSandbox.length,
          instances: iframesMissingSandbox.slice(0, 4),
        },
      },
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
      state: "confirmed",
      confidence: "high",
      title: "Embedded <iframe> Missing Lazy Loading",
      description: `${iframesMissingLazy.length} embedded iframe(s) do not use \`loading="lazy"\`.`,
      whyItMatters:
        "Non-lazy iframes eagerly download third-party embeds (videos, widgets) during initial page load, consuming bandwidth and CPU.",
      evidence: `Sample iframe: ${iframesMissingLazy[0]}`,
      structuredEvidence: {
        id: "ev-perf-iframe-lazy-missing",
        sourceUrl: finalUrl,
        affectedTarget: iframesMissingLazy[0],
        observation: `Detected ${iframesMissingLazy.length} embedded iframe(s) missing loading="lazy". Sample: ${iframesMissingLazy[0]}`,
        expectedCondition: "Embedded iframes specify loading='lazy'",
        evidenceType: "html-iframe-inspection",
        metadata: {
          count: iframesMissingLazy.length,
        },
      },
      affectedTarget: "HTML <iframe> Elements",
      recommendation: "Add `loading=\"lazy\"` to off-screen iframe embeds.",
      codeSnippet: '<iframe src="..." loading="lazy"></iframe>',
      instancesCount: iframesMissingLazy.length,
    });
  }

  return { findings, passedChecks };
}
