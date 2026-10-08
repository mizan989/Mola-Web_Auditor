import crypto from "node:crypto";
import type {
  Finding,
  FindingCategory,
  FindingPriority,
  PassedCheck,
  ScanResult,
} from "../types/audit.ts";
import { validateUrlAsync } from "./validators/url.ts";
import { performHttpInspection } from "./scanners/http.ts";
import { auditSecurity } from "./scanners/security.ts";
import { auditPerformance } from "./scanners/performance.ts";
import { auditSeo } from "./scanners/seo.ts";
import { auditAccessibility } from "./scanners/a11y.ts";
import { detectTechnologies } from "./scanners/tech.ts";
import { auditBestPractices } from "./scanners/bestPractices.ts";
import { auditDeepScan } from "./scanners/deep.ts";

export interface ScanOptions {
  url: string;
  mode?: "quick" | "deep";
}

const priorityOrder: Record<FindingPriority, number> = {
  critical: 4,
  "fix-first": 3,
  recommended: 2,
  investigate: 1,
};

const severityOrder = {
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Orchestrates a complete website audit with strict security validation and verifiable evidence.
 * Complies with SECURITY.md, PRD.md, and issues.md specifications.
 */
export async function runWebsiteAudit(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const scanMode = options.mode === "deep" ? "deep" : "quick";

  // Step 1: Validate URL and enforce comprehensive SSRF controls (ISSUE-001, ISSUE-002, ISSUE-003)
  const validation = await validateUrlAsync(options.url);
  if (!validation.isValid || !validation.normalizedUrl) {
    throw new Error(validation.error || "Invalid target URL.");
  }

  const targetUrl = validation.normalizedUrl;
  const hostname = new URL(targetUrl).hostname;
  // Replace Math.random with crypto.randomUUID() (ISSUE-034)
  const scanId = `mola-${crypto.randomUUID()}`;

  // Step 2: Controlled HTTP inspection with streaming limit and redirect tracking (ISSUE-010..014)
  const httpResult = await performHttpInspection(targetUrl);
  const { info, htmlText, finalUrl, rawHeaders, isTruncated } = httpResult;

  // Step 3: Run core audit engines
  const security = auditSecurity(rawHeaders, finalUrl, htmlText);
  const performance = auditPerformance(info.responseTimeMs, info.contentLength, rawHeaders, htmlText);
  const seo = auditSeo(htmlText);
  const accessibility = auditAccessibility(htmlText);
  const bestPractices = auditBestPractices(htmlText);
  const technologies = detectTechnologies(rawHeaders, htmlText);

  // Step 4: Run Deep Scan engine if requested (ISSUE-009, ISSUE-023)
  let deepFindings: Finding[] = [];
  let deepPassed: PassedCheck[] = [];
  if (scanMode === "deep") {
    const deepResult = auditDeepScan(rawHeaders, finalUrl, htmlText);
    deepFindings = deepResult.findings;
    deepPassed = deepResult.passedChecks;
  }

  // Step 5: Aggregate findings
  const allFindings: Finding[] = [
    ...security.findings,
    ...performance.findings,
    ...seo.findings,
    ...accessibility.findings,
    ...bestPractices.findings,
    ...deepFindings,
  ];

  if (isTruncated) {
    allFindings.push({
      id: "perf-payload-truncated",
      category: "performance",
      severity: "low",
      priority: "investigate",
      title: "Document Payload Exceeded Inspection Limit",
      description: "The remote document body exceeded the maximum 2.5 MB inspection limit and was safely capped.",
      whyItMatters:
        "Extremely large HTML payloads degrade mobile network performance, CPU parsing time, and memory usage.",
      evidence: `Body stream reached maximum size limit (2.5 MB); parsing terminated safely`,
      affectedTarget: "HTTP Response Body",
      recommendation: "Ensure initial server-rendered HTML documents remain under 1 MB.",
    });
  }

  const allPassed: PassedCheck[] = [
    ...security.passedChecks,
    ...performance.passedChecks,
    ...seo.passedChecks,
    ...accessibility.passedChecks,
    ...bestPractices.passedChecks,
    ...deepPassed,
  ];

  // Step 6: Sort findings deterministically by Severity then Priority
  allFindings.sort((a, b) => {
    const sevDiff = severityOrder[b.severity] - severityOrder[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return priorityOrder[b.priority] - priorityOrder[a.priority];
  });

  // Step 7: Calculate summary metrics
  const categoryCounts: Record<FindingCategory, number> = {
    security: 0,
    performance: 0,
    seo: 0,
    accessibility: 0,
    "best-practices": 0,
  };

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const f of allFindings) {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
    if (f.severity === "high") highCount++;
    else if (f.severity === "medium") mediumCount++;
    else if (f.severity === "low") lowCount++;
  }

  const scanDurationMs = Date.now() - startTime;
  const completeness = isTruncated ? "partial" : "full";
  const status = isTruncated ? "partial" : "completed";

  return {
    scanId,
    targetUrl,
    finalUrl,
    hostname,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs,
    scanMode,
    status,
    completeness,
    summary: {
      totalFindings: allFindings.length,
      highCount,
      mediumCount,
      lowCount,
      passedCount: allPassed.length,
      categoryCounts,
    },
    findings: allFindings,
    passedChecks: allPassed,
    technologies,
    httpInfo: info,
    performanceMetrics: performance.metrics,
    seoData: seo.seoData,
    accessibilitySummary: accessibility.summary,
  };
}

export { compareAuditResults } from "../lib/compare.ts";
