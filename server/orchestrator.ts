import type {
  Finding,
  FindingCategory,
  FindingConfidence,
  FindingPriority,
  FindingState,
  PassedCheck,
  ScanResult,
  BrowserExecutionResult,
} from "../types/audit.ts";
import { validateUrlAsync } from "./validators/url.ts";
import { performHttpInspection } from "./scanners/http.ts";
import { buildAuditContext } from "./context.ts";
import { auditSecurity } from "./scanners/security.ts";
import { auditPerformance } from "./scanners/performance.ts";
import { auditSeo } from "./scanners/seo.ts";
import { auditAccessibility } from "./scanners/a11y.ts";
import { auditBestPractices } from "./scanners/bestPractices.ts";
import { auditDeepScan } from "./scanners/deep.ts";
import { normalizeTraceableFinding } from "./evidenceEngine.ts";
import { enforceEvidenceQuality } from "./evidenceQuality.ts";
import { deduplicateFindings } from "./deduplication.ts";
import { executeIsolatedBrowserScan } from "./browser.ts";
import { calculateAuditCoverage } from "./coverage.ts";

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
export const OPERATION_DEADLINE_MS = 15000;

export async function runWebsiteAudit(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const scanMode = options.mode === "deep" ? "deep" : "quick";

  // Master operation deadline covering the entire lifecycle: validation, DNS, HTTP inspection, and modules
  const masterController = new AbortController();
  const deadlineTimeout = setTimeout(() => masterController.abort(), OPERATION_DEADLINE_MS);

  try {
    // Step 1: Validate URL and enforce comprehensive SSRF controls with DNS timeout integrated into the master operation deadline
    const validation = await validateUrlAsync(options.url, {
      signal: masterController.signal,
      timeoutMs: 5000,
    });
    if (!validation.isValid || !validation.normalizedUrl) {
      throw new Error(validation.error || "Invalid target URL.");
    }

    const targetUrl = validation.normalizedUrl;
    // Replace Math.random with crypto.randomUUID() (ISSUE-034)
    const scanId = `mola-${crypto.randomUUID()}`;

    // Step 2: Controlled HTTP inspection with streaming limit and redirect tracking, integrated into master deadline
    const remainingMs = Math.max(1000, OPERATION_DEADLINE_MS - (Date.now() - startTime));
    const httpResult = await performHttpInspection(targetUrl, {
      signal: masterController.signal,
      timeoutMs: remainingMs,
    });

    // Step 3: Construct authoritative shared AuditContext (Phase 2)
    const context = buildAuditContext({
      targetUrl,
      finalUrl: httpResult.finalUrl,
      scanMode,
      scanId,
      startTime,
      httpResult,
      validatedAddresses: validation.resolvedAddresses,
    });

  // Step 4: Run core audit engines consuming the shared AuditContext
  const security = auditSecurity(context);
  const performance = auditPerformance(context);
  const seo = auditSeo(context);
  const accessibility = auditAccessibility(context);
  const bestPractices = auditBestPractices(context);
  const technologies = context.technologyObservations;

  // Step 5: Run Deep Scan engine if requested (ISSUE-009, ISSUE-023, Phase 10)
  let deepFindings: Finding[] = [];
  let deepPassed: PassedCheck[] = [];
  let browserExecution: BrowserExecutionResult | undefined;

  if (scanMode === "deep") {
    const deepResult = auditDeepScan(context);
    deepFindings = deepResult.findings;
    deepPassed = deepResult.passedChecks;

    // Phase 10: Isolated Browser Execution for Deep Scan
    browserExecution = await executeIsolatedBrowserScan(context);
    if (browserExecution.findings && browserExecution.findings.length > 0) {
      deepFindings.push(...browserExecution.findings);
    }
    if (browserExecution.passedChecks && browserExecution.passedChecks.length > 0) {
      deepPassed.push(...browserExecution.passedChecks);
    }
    if (browserExecution.limitationReason) {
      context.limitations.push(browserExecution.limitationReason);
    }
  }

  // Step 6: Aggregate findings
  const allFindings: Finding[] = [
    ...security.findings,
    ...performance.findings,
    ...seo.findings,
    ...accessibility.findings,
    ...bestPractices.findings,
    ...deepFindings,
  ];

  if (context.body.isTruncated && !allFindings.some((f) => f.id === "perf-payload-truncated")) {
    allFindings.push({
      id: "perf-payload-truncated",
      category: "performance",
      severity: "low",
      priority: "investigate",
      state: "observation",
      confidence: "high",
      title: "Document Payload Exceeded Inspection Limit",
      description: "The remote document body exceeded the maximum 2.5 MB inspection limit and was safely capped.",
      whyItMatters:
        "Extremely large HTML payloads degrade mobile network performance, CPU parsing time, and memory usage.",
      evidence: `Body stream reached maximum size limit (2.5 MB); parsing terminated safely`,
      structuredEvidence: {
        id: "ev-perf-payload-truncated",
        sourceUrl: context.finalUrl,
        affectedTarget: "HTTP Response Body",
        observation: "Body stream reached maximum size limit (2.5 MB); parsing terminated safely.",
        expectedCondition: "HTML payload within bounded stream inspection limit (<= 2.5 MB)",
        evidenceType: "stream-limit-inspection",
        limitations: "Document inspection truncated at 2.5 MB; downstream DOM nodes beyond this limit were not inspected.",
      },
      affectedTarget: "HTTP Response Body",
      recommendation: "Ensure initial server-rendered HTML documents remain under 1 MB.",
      limitations: "Document inspection truncated at 2.5 MB; downstream DOM nodes beyond this limit were not inspected.",
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

  // Step 6: First-Class Evidence Normalization & Quality Rules (Phase 6 & Phase 7)
  const traceableFindings: Finding[] = allFindings
    .map((f) => normalizeTraceableFinding(f, context.finalUrl))
    .map(enforceEvidenceQuality);

  // Step 7: Deterministic Semantic Correlation & Deduplication (Phase 9)
  const deduplicatedFindings: Finding[] = deduplicateFindings(traceableFindings);

  // Step 8: Sort findings deterministically by Severity then Priority
  deduplicatedFindings.sort((a, b) => {
    const sevDiff = severityOrder[b.severity] - severityOrder[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return priorityOrder[b.priority] - priorityOrder[a.priority];
  });

  // Step 9: Calculate summary metrics
  const categoryCounts: Record<FindingCategory, number> = {
    security: 0,
    performance: 0,
    seo: 0,
    accessibility: 0,
    "best-practices": 0,
  };

  const stateCounts: Record<FindingState, number> = {
    confirmed: 0,
    not_detected: 0,
    unable_to_check: 0,
    failed: 0,
    observation: 0,
    recommendation: 0,
  };

  const confidenceCounts: Record<FindingConfidence, number> = {
    high: 0,
    medium: 0,
    low: 0,
  };

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const f of deduplicatedFindings) {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
    if (f.severity === "high") highCount++;
    else if (f.severity === "medium") mediumCount++;
    else if (f.severity === "low") lowCount++;

    if (f.state) {
      stateCounts[f.state] = (stateCounts[f.state] || 0) + 1;
    }
    if (f.confidence) {
      confidenceCounts[f.confidence] = (confidenceCounts[f.confidence] || 0) + 1;
    }
  }

  const scanDurationMs = Date.now() - startTime;
  const isTruncated = context.body.isTruncated;
  const completeness = isTruncated ? "partial" : "full";
  const status = isTruncated ? "partial" : "completed";

  return {
    scanId,
    targetUrl,
    finalUrl: context.finalUrl,
    hostname: context.hostname,
    scanTimestamp: new Date().toISOString(),
    scanDurationMs,
    scanMode,
    status,
    completeness,
    summary: {
      totalFindings: deduplicatedFindings.length,
      highCount,
      mediumCount,
      lowCount,
      passedCount: allPassed.length,
      categoryCounts,
      stateCounts,
      confidenceCounts,
    },
    findings: deduplicatedFindings,
    passedChecks: allPassed,
    technologies,
    httpInfo: httpResult.info,
    performanceMetrics: performance.metrics,
    seoData: seo.seoData,
    accessibilitySummary: accessibility.summary,
    reconnaissance: context.recon,
    limitations: context.limitations.length > 0 ? [...context.limitations] : undefined,
    browserExecution,
    coverage: calculateAuditCoverage(
      context,
      deduplicatedFindings,
      allPassed,
      browserExecution
    ),
  };
  } finally {
    clearTimeout(deadlineTimeout);
  }
}

export { compareAuditResults } from "../lib/compare.ts";
export { buildAuditContext, createPartialAuditContext, isAuditContext } from "./context.ts";
export { collectReconnaissance, extractDiscoveredResources } from "./recon.ts";
export { calculateAuditCoverage } from "./coverage.ts";
