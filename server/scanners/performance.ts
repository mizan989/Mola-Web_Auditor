import type { AuditContext, Finding, PassedCheck, PerformanceMetrics } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import {
  parseHtmlDocument,
  extractDiscoveredResourcesFromDom,
  extractScripts,
} from "../htmlParser.ts";
import { auditHttpInfrastructure } from "../modules/httpInfrastructure.ts";

export interface PerformanceAuditResult {
  metrics: PerformanceMetrics;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Audits frontend performance, network delivery, and DOM rendering characteristics.
 * Composes specialized HTTP/Infrastructure checks (TTFB, compression, caching) with DOM inspections.
 */
export function auditPerformance(
  contextOrResponseTime: AuditContext | number,
  legacyContentLength?: number,
  legacyHeaders?: Record<string, string>,
  legacyHtmlText?: string
): PerformanceAuditResult {
  const isCtx = isAuditContext(contextOrResponseTime);
  const responseTimeMs = isCtx ? contextOrResponseTime.timing.ttfbMs : (contextOrResponseTime as number);
  const contentLength = isCtx ? contextOrResponseTime.response.contentLength : (legacyContentLength || 0);
  const headers = isCtx ? contextOrResponseTime.headers : (legacyHeaders || {});
  const htmlText = isCtx ? contextOrResponseTime.body.text : (legacyHtmlText || "");
  const isTruncated = isCtx ? contextOrResponseTime.body.isTruncated : false;
  const finalUrl = isCtx ? contextOrResponseTime.finalUrl : "";
  const context = isCtx ? contextOrResponseTime : undefined;

  // 1. Evaluate HTTP infrastructure checks (TTFB latency, compression, caching, truncation)
  const infraResult = auditHttpInfrastructure({
    responseTimeMs,
    contentLength,
    headers,
    isTruncated,
    finalUrl,
  });

  const findings: Finding[] = [...infraResult.findings];
  const passedChecks: PassedCheck[] = [...infraResult.passedChecks];

  const encoding = headers["content-encoding"] || null;
  const cacheControl = headers["cache-control"] || null;
  const payloadKb = Math.round((contentLength / 1024) * 10) / 10;

  // Extract scripts, styles, images (or leverage context.discoveredResources if available)
  const root = parseHtmlDocument(htmlText);
  const discovered = context?.discoveredResources || extractDiscoveredResourcesFromDom(root);
  const scriptsCount = discovered.scripts.length;
  const stylesheetsCount = discovered.stylesheets.length;
  const imagesCount = discovered.images.length;

  const metrics: PerformanceMetrics = {
    ttfbMs: responseTimeMs,
    totalPayloadKb: payloadKb,
    compression: encoding,
    cacheControl,
    scriptsCount,
    stylesheetsCount,
    imagesCount,
  };

  // 2. Render-blocking scripts in <head>
  const scriptsInDoc = extractScripts(root);
  const blockingScripts: string[] = [];

  for (const s of scriptsInDoc) {
    if (s.inHead && s.src && !s.isAsync && !s.isDefer && !s.isModule && !s.isNoModule) {
      blockingScripts.push(s.src);
    }
  }

  if (blockingScripts.length > 0) {
    findings.push({
      id: "perf-render-blocking-scripts",
      category: "performance",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Render-Blocking Scripts in <head>",
      description: `Found ${blockingScripts.length} synchronous <script> tags in the document <head>.`,
      whyItMatters:
        "Synchronous scripts halt HTML parsing until the script is fully downloaded and executed, directly delaying First Contentful Paint (FCP).",
      evidence: `Sample blocking script: ${blockingScripts[0]?.slice(0, 80) || ""}`,
      structuredEvidence: {
        id: "ev-perf-render-blocking-scripts",
        affectedTarget: "<head> scripts",
        observation: `Found ${blockingScripts.length} synchronous <script> tags in <head>`,
        expectedCondition: "Scripts deferred, async, or loaded as ES modules",
        evidenceType: "dom-inspection",
        metadata: { blockingCount: blockingScripts.length },
      },
      affectedTarget: "<head> scripts",
      recommendation: "Add `defer` or `async` to non-critical external scripts, or adopt ES modules.",
      codeSnippet: '<script src="..." defer></script>',
      instancesCount: blockingScripts.length,
      instances: blockingScripts.slice(0, 4),
    });
  } else {
    passedChecks.push({
      id: "perf-scripts-deferred",
      category: "performance",
      state: "not_detected",
      confidence: "high",
      structuredEvidence: {
        id: "ev-perf-scripts-deferred",
        affectedTarget: "<head> scripts",
        observation: "Zero synchronous render-blocking scripts detected in <head>",
        expectedCondition: "Scripts deferred or asynchronous",
        evidenceType: "dom-inspection",
      },
      title: "All Scripts Asynchronous or Deferred",
      detail: "No synchronous render-blocking scripts detected in document <head>.",
    });
  }

  // 3. Image dimension declaration (CLS reduction)
  const imgEls = root.querySelectorAll("img");
  const imagesWithoutDimensions: string[] = [];

  for (const img of imgEls) {
    const width = img.getAttribute("width");
    const height = img.getAttribute("height");
    const hasWidth = Boolean(width && /^\d+/.test(width.trim()));
    const hasHeight = Boolean(height && /^\d+/.test(height.trim()));
    if (!hasWidth || !hasHeight) {
      imagesWithoutDimensions.push(img.outerHTML ? img.outerHTML.replace(/\s+/g, " ").slice(0, 75) : "<img>");
    }
  }

  if (imagesWithoutDimensions.length > 0) {
    findings.push({
      id: "perf-images-missing-dimensions",
      category: "performance",
      severity: "low",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Images Missing Explicit Dimensions",
      description: `${imagesWithoutDimensions.length} image(s) lack explicit width and height attributes.`,
      whyItMatters:
        "When browsers do not know an image's aspect ratio beforehand, the page layout shifts abruptly as images load, hurting Cumulative Layout Shift (CLS).",
      evidence: `Sample image tag: ${imagesWithoutDimensions[0]?.slice(0, 75) || ""}`,
      structuredEvidence: {
        id: "ev-perf-images-missing-dimensions",
        affectedTarget: "HTML <img> Elements",
        observation: `${imagesWithoutDimensions.length} <img> elements lack width and height attributes`,
        expectedCondition: "All <img> elements declare explicit width and height",
        evidenceType: "dom-inspection",
        metadata: { missingCount: imagesWithoutDimensions.length },
      },
      affectedTarget: "HTML <img> Elements",
      recommendation:
        "Specify explicit `width` and `height` attributes or CSS aspect-ratio on all image elements.",
      codeSnippet: '<img src="/photo.jpg" width="800" height="600" alt="..." />',
      instancesCount: imagesWithoutDimensions.length,
      instances: imagesWithoutDimensions.slice(0, 5),
    });
  }

  return { metrics, findings, passedChecks };
}
