import {
  Finding,
  FindingCategory,
  FindingPriority,
  PassedCheck,
  ScanResult,
  VerificationComparison,
} from "@/types/audit";
import { validateAndSanitizeUrl } from "./validators/url";
import { performHttpInspection } from "./scanners/http";
import { auditSecurity } from "./scanners/security";
import { auditPerformance } from "./scanners/performance";
import { auditSeo } from "./scanners/seo";
import { auditAccessibility } from "./scanners/a11y";
import { detectTechnologies } from "./scanners/tech";
import { auditBestPractices } from "./scanners/bestPractices";

export interface ScanOptions {
  url: string;
  mode?: "quick" | "deep";
}

/**
 * Priority scoring helper for ordering findings
 */
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
 * Runs a complete audit on the given URL following PRD.md and SECURITY.md guidelines.
 */
export async function runWebsiteAudit(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const scanMode = options.mode === "deep" ? "deep" : "quick";

  // Step 1: Validate URL & enforce SSRF controls
  const validation = validateAndSanitizeUrl(options.url);
  if (!validation.isValid || !validation.normalizedUrl) {
    throw new Error(validation.error || "Invalid target URL.");
  }

  const targetUrl = validation.normalizedUrl;
  const hostname = new URL(targetUrl).hostname;
  const scanId = `mola-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

  // Step 2: Perform controlled HTTP inspection
  const httpResult = await performHttpInspection(targetUrl);
  const { info, htmlText, finalUrl, rawHeaders } = httpResult;

  // Step 3: Run all audit engines
  const security = auditSecurity(rawHeaders, finalUrl, htmlText);
  const performance = auditPerformance(info.responseTimeMs, info.contentLength, rawHeaders, htmlText);
  const seo = auditSeo(htmlText);
  const accessibility = auditAccessibility(htmlText);
  const bestPractices = auditBestPractices(htmlText);
  const technologies = detectTechnologies(rawHeaders, htmlText);

  // Step 4: Aggregate findings and passed checks
  const allFindings: Finding[] = [
    ...security.findings,
    ...performance.findings,
    ...seo.findings,
    ...accessibility.findings,
    ...bestPractices.findings,
  ];

  const allPassed: PassedCheck[] = [
    ...security.passedChecks,
    ...performance.passedChecks,
    ...seo.passedChecks,
    ...accessibility.passedChecks,
    ...bestPractices.passedChecks,
  ];

  // Step 5: Normalize and Sort Findings by Severity and Priority
  allFindings.sort((a, b) => {
    const sevDiff = severityOrder[b.severity] - severityOrder[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return priorityOrder[b.priority] - priorityOrder[a.priority];
  });

  // Step 6: Calculate Summary Counts
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

  return {
    scanId,
    targetUrl,
    finalUrl,
    hostname,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs,
    scanMode,
    status: "completed",
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

/**
 * Compares two audit results for the Fix Verification loop (PRD.md F-017).
 */
export function compareAuditResults(
  previousResult: ScanResult,
  newResult: ScanResult
): VerificationComparison {
  const prevIds = new Set(previousResult.findings.map((f) => f.id));
  const newIds = new Set(newResult.findings.map((f) => f.id));

  // Resolved = was in previous scan, but not in new scan
  const resolvedFindings = previousResult.findings.filter((f) => !newIds.has(f.id));

  // Remaining = present in both scans
  const remainingFindings = newResult.findings.filter((f) => prevIds.has(f.id));

  // New = present in new scan, but was not in previous scan
  const newFindings = newResult.findings.filter((f) => !prevIds.has(f.id));

  return {
    previousScanTimestamp: previousResult.scanTimestamp,
    newScanTimestamp: newResult.scanTimestamp,
    targetUrl: newResult.targetUrl,
    resolvedFindings,
    remainingFindings,
    newFindings,
    totalPrevious: previousResult.findings.length,
    totalCurrent: newResult.findings.length,
  };
}
