/**
 * Phase 8: Specialized Audit Modules Registry & Unified Dispatcher.
 *
 * Exposes 11 focused domain audit modules:
 * 1. HTTP / Infrastructure (auditHttpInfrastructure)
 * 2. Security Headers (auditSecurityHeaders)
 * 3. Cookies (auditCookies)
 * 4. TLS Observations (auditTls)
 * 5. Mixed Content (auditMixedContent)
 * 6. SEO (auditSeo)
 * 7. Accessibility (auditAccessibility)
 * 8. Best Practices (auditBestPractices)
 * 9. Technology Detection (detectTechnologies)
 * 10. Resource Integrity (auditResourceIntegrity)
 * 11. Iframe & Resource Safety (auditIframeSafety)
 */

import type {
  AuditContext,
  DetectedTechnology,
  Finding,
  PassedCheck,
  PerformanceMetrics,
  SeoInspection,
  AccessibilityInspection,
} from "../../types/audit.ts";

export { auditHttpInfrastructure, type HttpInfrastructureResult, type HttpInfrastructureOptions } from "./httpInfrastructure.ts";
export { auditSecurityHeaders, type SecurityHeadersAuditResult } from "./securityHeaders.ts";
export { auditCookies, type CookiesAuditResult } from "./cookies.ts";
export { auditTls, type TlsAuditResult } from "./tls.ts";
export { auditMixedContent, type MixedContentAuditResult } from "./mixedContent.ts";
export { auditSeo, type SeoAuditResult } from "./seo.ts";
export { auditAccessibility, type A11yAuditResult } from "./accessibility.ts";
export { auditBestPractices, type BestPracticesAuditResult } from "./bestPractices.ts";
export { detectTechnologies } from "./techDetection.ts";
export { auditResourceIntegrity, type ResourceIntegrityAuditResult } from "./resourceIntegrity.ts";
export { auditIframeSafety, type IframeSafetyAuditResult } from "./iframeSafety.ts";

import { auditHttpInfrastructure } from "./httpInfrastructure.ts";
import { auditSecurityHeaders } from "./securityHeaders.ts";
import { auditCookies } from "./cookies.ts";
import { auditTls } from "./tls.ts";
import { auditMixedContent } from "./mixedContent.ts";
import { auditSeo } from "./seo.ts";
import { auditAccessibility } from "./accessibility.ts";
import { auditBestPractices } from "./bestPractices.ts";
import { detectTechnologies } from "./techDetection.ts";
import { auditResourceIntegrity } from "./resourceIntegrity.ts";
import { auditIframeSafety } from "./iframeSafety.ts";
import { parseHtmlDocument, extractDiscoveredResourcesFromDom, extractScripts } from "../htmlParser.ts";

export interface AuditModulesExecutionOptions {
  mode?: "quick" | "deep";
}

export interface AuditModulesResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
  detectedTechnologies: DetectedTechnology[];
  seoData: SeoInspection;
  a11ySummary: AccessibilityInspection;
  performanceMetrics: PerformanceMetrics;
}

/**
 * Runs all 11 specialized audit modules against the shared authoritative AuditContext.
 */
export function runAllAuditModules(
  context: AuditContext,
  options?: AuditModulesExecutionOptions
): AuditModulesResult {
  const scanMode = options?.mode || context.scanMode || "quick";

  // 1. HTTP / Infrastructure
  const httpInfra = auditHttpInfrastructure(context);

  // If connection failed completely, abort early with connection limitation
  if (httpInfra.findings.some((f) => f.id === "sec-connection-failed")) {
    return {
      findings: httpInfra.findings,
      passedChecks: httpInfra.passedChecks,
      detectedTechnologies: [],
      seoData: {
        title: null,
        titleLength: 0,
        metaDescription: null,
        descriptionLength: 0,
        canonicalUrl: null,
        robots: null,
        ogTitle: null,
        ogImage: null,
        h1Count: 0,
        headings: [],
      },
      a11ySummary: {
        imagesTotal: 0,
        imagesMissingAlt: 0,
        missingAltElements: [],
        hasLang: false,
        lang: null,
        hasMainLandmark: false,
        hasHeaderLandmark: false,
        inputsMissingLabel: 0,
      },
      performanceMetrics: {
        ttfbMs: 0,
        totalPayloadKb: 0,
        compression: null,
        cacheControl: null,
        scriptsCount: 0,
        stylesheetsCount: 0,
        imagesCount: 0,
      },
    };
  }

  // 2. TLS Observations
  const tls = auditTls(context);

  // 3. Security Headers
  const secHeaders = auditSecurityHeaders(context);

  // 4. Mixed Content
  const mixedContent = auditMixedContent(context);

  // 5. SEO
  const seo = auditSeo(context);

  // 6. Accessibility
  const a11y = auditAccessibility(context);

  // 7. Best Practices
  const bestPractices = auditBestPractices(context);

  // 8. Technology Detection
  const technologies = detectTechnologies(context);

  // 9. Resource Integrity, Cookies, Iframe Safety (Deep scan or applicable)
  const integrity = scanMode === "deep" ? auditResourceIntegrity(context) : { findings: [], passedChecks: [] };
  const cookies = scanMode === "deep" ? auditCookies(context) : { findings: [], passedChecks: [] };
  const iframeSafety = scanMode === "deep" ? auditIframeSafety(context) : { findings: [], passedChecks: [] };

  // Calculate rendering and DOM metrics for performance
  const root = parseHtmlDocument(context.body.text);
  const discovered = context.discoveredResources || extractDiscoveredResourcesFromDom(root);
  const scriptsInDoc = extractScripts(root);
  const blockingScripts: string[] = [];
  for (const s of scriptsInDoc) {
    if (s.inHead && s.src && !s.isAsync && !s.isDefer && !s.isModule && !s.isNoModule) {
      blockingScripts.push(s.src);
    }
  }

  const perfDomFindings: Finding[] = [];
  const perfDomPassed: PassedCheck[] = [];

  if (blockingScripts.length > 0) {
    perfDomFindings.push({
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
    perfDomPassed.push({
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
    perfDomFindings.push({
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

  const allFindings: Finding[] = [
    ...httpInfra.findings,
    ...tls.findings,
    ...secHeaders.findings,
    ...mixedContent.findings,
    ...seo.findings,
    ...a11y.findings,
    ...bestPractices.findings,
    ...integrity.findings,
    ...cookies.findings,
    ...iframeSafety.findings,
    ...perfDomFindings,
  ];

  const allPassed: PassedCheck[] = [
    ...httpInfra.passedChecks,
    ...tls.passedChecks,
    ...secHeaders.passedChecks,
    ...mixedContent.passedChecks,
    ...seo.passedChecks,
    ...a11y.passedChecks,
    ...bestPractices.passedChecks,
    ...integrity.passedChecks,
    ...cookies.passedChecks,
    ...iframeSafety.passedChecks,
    ...perfDomPassed,
  ];

  const performanceMetrics: PerformanceMetrics = {
    ttfbMs: context.timing.ttfbMs,
    totalPayloadKb: Math.round((context.response.contentLength / 1024) * 10) / 10,
    compression: context.headers["content-encoding"] || null,
    cacheControl: context.headers["cache-control"] || null,
    scriptsCount: discovered.scripts.length,
    stylesheetsCount: discovered.stylesheets.length,
    imagesCount: discovered.images.length,
  };

  return {
    findings: allFindings,
    passedChecks: allPassed,
    detectedTechnologies: technologies,
    seoData: seo.seoData,
    a11ySummary: a11y.summary,
    performanceMetrics,
  };
}
