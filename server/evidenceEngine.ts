/**
 * First-Class Evidence Engine (Phase 6).
 *
 * Guarantees that EVERY finding answers the 6 fundamental questions:
 * 1. What was observed?
 * 2. Where?
 * 3. How?
 * 4. Why does it matter?
 * 5. What limitation exists?
 * 6. What should the developer do?
 *
 * Enforces rigorous traceability and ensures exported evidence matches internal evidence.
 */

import type {
  Finding,
  FindingCategory,
  FindingSeverity,
  FindingPriority,
  FindingState,
  FindingConfidence,
  StructuredEvidence,
} from "../types/audit.ts";

export interface TraceableEvidenceAnswers {
  whatWasObserved: string;
  where: string;
  howObserved: string;
  whyItMatters: string;
  limitations: string;
  whatToDo: string;
}

export interface FindingBuilderSpec {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  priority: FindingPriority;
  state?: FindingState;
  confidence?: FindingConfidence;
  title: string;
  description: string;
  whyItMatters: string;
  evidence: string;
  affectedTarget: string;
  recommendation: string;
  howObserved?: string;
  limitations?: string;
  sourceUrl?: string;
  expectedCondition?: string;
  metadata?: Record<string, unknown>;
  codeSnippet?: string;
  instancesCount?: number;
  instances?: string[];
}

/**
 * Determines the authoritative methodology by which the condition was observed.
 */
export function determineHowObserved(id: string, category: FindingCategory, affectedTarget: string): string {
  if (id.startsWith("sec-connection-") || id === "sec-connection-failed") {
    return "network-failure";
  }

  if (
    id.startsWith("sec-hsts") ||
    id.startsWith("sec-csp") ||
    id.startsWith("sec-xfo") ||
    id.startsWith("sec-xcto") ||
    id.startsWith("sec-referrer") ||
    id.startsWith("sec-permissions") ||
    id.startsWith("sec-server") ||
    id.startsWith("sec-x-powered") ||
    id.startsWith("sec-cookie") ||
    id.startsWith("perf-compression") ||
    id.startsWith("perf-cache") ||
    affectedTarget.toLowerCase().includes("header")
  ) {
    return "header-inspection";
  }

  if (
    id.startsWith("perf-high-ttfb") ||
    id.startsWith("perf-moderate-ttfb") ||
    affectedTarget.toLowerCase().includes("latency") ||
    affectedTarget.toLowerCase().includes("timing")
  ) {
    return "timing-measurement";
  }

  if (id.startsWith("perf-payload") || affectedTarget.toLowerCase().includes("stream")) {
    return "response-measurement";
  }

  if (
    category === "seo" ||
    category === "accessibility" ||
    category === "best-practices" ||
    id.startsWith("sec-mixed-content") ||
    id.startsWith("sec-sri") ||
    id.startsWith("sec-iframe") ||
    id.startsWith("perf-iframe") ||
    id.startsWith("perf-render-blocking")
  ) {
    return "dom-inspection";
  }

  return "static-analysis";
}

/**
 * Determines realistic, truthful limitations of the inspection technique.
 */
export function determineDefaultLimitations(id: string, category: FindingCategory, howObserved: string): string {
  if (howObserved === "network-failure") {
    return "Audit halted prematurely; remote host was unreachable, timed out, or blocked by connection policy.";
  }

  if (howObserved === "header-inspection") {
    return "Evaluated from initial HTTP response headers; edge CDN caching or reverse-proxy routing rules may alter headers for different user agents or geographies.";
  }

  if (howObserved === "dom-inspection") {
    return "Evaluated from initial static server-rendered HTML; client-side DOM mutations, SPA hydration, and user interactions were not executed in Quick Scan mode.";
  }

  if (howObserved === "timing-measurement") {
    return "Point-in-time network latency measurement subject to transient network congestion, geographic distance, and edge routing variability.";
  }

  if (howObserved === "response-measurement") {
    return "Evaluated against HTTP response stream up to the 2.5 MB inspection ceiling; downstream bytes beyond the cap were not inspected.";
  }

  return "Automated static analysis limited to the initial HTTP response cycle; dynamic runtime behavior may differ.";
}

/**
 * Builds a standardized Finding guaranteeing full 6-question traceability.
 */
export function buildFinding(spec: FindingBuilderSpec): Finding {
  const howObserved = spec.howObserved || determineHowObserved(spec.id, spec.category, spec.affectedTarget);
  const limitations = spec.limitations || determineDefaultLimitations(spec.id, spec.category, howObserved);

  const structuredEvidence: StructuredEvidence = {
    id: `ev-${spec.id}`,
    sourceUrl: spec.sourceUrl,
    affectedTarget: spec.affectedTarget,
    observation: spec.evidence,
    expectedCondition: spec.expectedCondition,
    evidenceType: howObserved,
    metadata: spec.metadata,
    limitations,
    // Explicit 6-question dimensions (Phase 6):
    whatWasObserved: spec.evidence,
    where: spec.affectedTarget,
    howObserved,
    whyItMatters: spec.whyItMatters,
    whatToDo: spec.recommendation,
  };

  return {
    id: spec.id,
    category: spec.category,
    severity: spec.severity,
    priority: spec.priority,
    state: spec.state || "confirmed",
    confidence: spec.confidence || "high",
    title: spec.title,
    description: spec.description,
    whyItMatters: spec.whyItMatters,
    evidence: spec.evidence,
    structuredEvidence,
    affectedTarget: spec.affectedTarget,
    recommendation: spec.recommendation,
    codeSnippet: spec.codeSnippet,
    instancesCount: spec.instancesCount,
    instances: spec.instances,
    limitations,
  };
}

/**
 * Normalizes any finding to guarantee all 6 evidence dimensions are populated and synchronized.
 */
export function normalizeTraceableFinding(finding: Finding, defaultSourceUrl?: string): Finding {
  const existingSe = finding.structuredEvidence;

  // 1. What was observed?
  const whatWasObserved =
    existingSe?.whatWasObserved ||
    existingSe?.observation ||
    finding.evidence ||
    finding.description ||
    "Observed issue condition";

  // 2. Where?
  const where =
    existingSe?.where ||
    existingSe?.affectedTarget ||
    finding.affectedTarget ||
    defaultSourceUrl ||
    "Target Resource";

  // 3. How?
  const howObserved =
    existingSe?.howObserved ||
    existingSe?.evidenceType ||
    determineHowObserved(finding.id, finding.category, where);

  // 4. Why does it matter?
  const whyItMatters =
    existingSe?.whyItMatters ||
    finding.whyItMatters ||
    "May impact security, accessibility, performance, or SEO.";

  // 5. What limitation exists?
  const limitations =
    finding.limitations ||
    existingSe?.limitations ||
    determineDefaultLimitations(finding.id, finding.category, howObserved);

  // 6. What should the developer do?
  const whatToDo =
    existingSe?.whatToDo ||
    finding.recommendation ||
    "Review and remediate according to best practices.";

  const structuredEvidence: StructuredEvidence = {
    id: existingSe?.id || `ev-${finding.id}`,
    sourceUrl: existingSe?.sourceUrl || defaultSourceUrl,
    affectedTarget: where,
    observation: whatWasObserved,
    expectedCondition: existingSe?.expectedCondition,
    evidenceType: howObserved,
    metadata: existingSe?.metadata,
    limitations,
    whatWasObserved,
    where,
    howObserved,
    whyItMatters,
    whatToDo,
  };

  return {
    ...finding,
    evidence: whatWasObserved,
    affectedTarget: where,
    whyItMatters,
    limitations,
    recommendation: whatToDo,
    structuredEvidence,
  };
}

/**
 * Extracts the 6 core answers from any Finding.
 */
export function extractTraceableAnswers(finding: Finding): TraceableEvidenceAnswers {
  const normalized = normalizeTraceableFinding(finding);
  const se = normalized.structuredEvidence!;

  return {
    whatWasObserved: se.whatWasObserved!,
    where: se.where!,
    howObserved: se.howObserved!,
    whyItMatters: se.whyItMatters!,
    limitations: se.limitations!,
    whatToDo: se.whatToDo!,
  };
}

/**
 * Asserts that a finding contains non-empty answers to all 6 core questions.
 */
export function validateFindingTraceability(finding: Finding): {
  isValid: boolean;
  missing: string[];
  answers: TraceableEvidenceAnswers;
} {
  const answers = extractTraceableAnswers(finding);
  const missing: string[] = [];

  if (!answers.whatWasObserved || !answers.whatWasObserved.trim()) missing.push("1. What was observed?");
  if (!answers.where || !answers.where.trim()) missing.push("2. Where?");
  if (!answers.howObserved || !answers.howObserved.trim()) missing.push("3. How?");
  if (!answers.whyItMatters || !answers.whyItMatters.trim()) missing.push("4. Why does it matter?");
  if (!answers.limitations || !answers.limitations.trim()) missing.push("5. What limitation exists?");
  if (!answers.whatToDo || !answers.whatToDo.trim()) missing.push("6. What should the developer do?");

  return {
    isValid: missing.length === 0,
    missing,
    answers,
  };
}

/**
 * Validates that an entire collection of findings strictly satisfies Phase 6 evidence criteria.
 */
export function verifyAuditEvidenceTraceability(findings: Finding[]): {
  allValid: boolean;
  invalidCount: number;
  report: Record<string, string[]>;
} {
  const report: Record<string, string[]> = {};
  let invalidCount = 0;

  for (const finding of findings) {
    const result = validateFindingTraceability(finding);
    if (!result.isValid) {
      invalidCount++;
      report[finding.id] = result.missing;
    }
  }

  return {
    allValid: invalidCount === 0,
    invalidCount,
    report,
  };
}
