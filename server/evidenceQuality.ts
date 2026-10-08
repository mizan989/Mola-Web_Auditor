/**
 * Evidence-Quality Rules & Independent Severity/Confidence Engine (Phase 7).
 *
 * Implements the core principles:
 * 1. Severity = Impact if true (high | medium | low).
 * 2. Confidence = Certainty that the condition is true (high | medium | low).
 * 3. Evidence-Quality Rules:
 *    - Direct evidence can be high confidence.
 *    - Strong structural inference may be medium or high confidence.
 *    - Heuristic evidence must not be presented as certainty.
 *    - Unsupported inference cannot become a confirmed finding.
 * 4. Strictly bans numeric confidence scores and global vanity scores.
 * 5. Clearly marks uncertain observations.
 */

import type {
  Finding,
  FindingSeverity,
  FindingConfidence,
  FindingState,
} from "../types/audit.ts";

export type EvidenceQualityTier = "direct" | "structural" | "heuristic" | "unsupported";

export interface EvidenceQualityEvaluation {
  tier: EvidenceQualityTier;
  confidence: FindingConfidence;
  state: FindingState;
  severity: FindingSeverity;
  rationale: string;
}

/**
 * Evaluates the evidence quality tier based on observation method, evidence type, and telemetry.
 */
export function classifyEvidenceQuality(finding: Finding): EvidenceQualityEvaluation {
  const how = finding.structuredEvidence?.howObserved || finding.structuredEvidence?.evidenceType || "";
  const id = finding.id;
  const state = finding.state || "confirmed";
  const severity = finding.severity;

  // 1. Unsupported inference check (e.g. network failure, timeout, uninspected target)
  if (
    how === "network-failure" ||
    id.startsWith("sec-connection-") ||
    state === "unable_to_check" ||
    state === "failed"
  ) {
    return {
      tier: "unsupported",
      confidence: "high", // High certainty that we could not inspect
      state: "unable_to_check",
      severity,
      rationale: "Network unreachable or connection aborted; condition is uninspected, not a confirmed defect.",
    };
  }

  // 2. Direct evidence check (exact header presence/absence, exact DOM elements, direct status)
  const isDirectHeader =
    how === "header-inspection" &&
    (id.startsWith("sec-hsts") ||
      id.startsWith("sec-csp-missing") ||
      id.startsWith("sec-xfo") ||
      id.startsWith("sec-xcto") ||
      id.startsWith("sec-referrer") ||
      id.startsWith("sec-permissions") ||
      id.startsWith("sec-server") ||
      id.startsWith("sec-x-powered") ||
      id.startsWith("perf-compression") ||
      id.startsWith("perf-cache"));

  const isDirectDom =
    how === "dom-inspection" &&
    (id === "seo-title-missing" ||
      id === "seo-meta-description-missing" ||
      id === "seo-viewport-missing" ||
      id === "seo-h1-missing" ||
      id === "bp-doctype-missing" ||
      id === "bp-charset-missing" ||
      id === "bp-deprecated-tags" ||
      id === "a11y-html-lang-missing" ||
      id === "a11y-images-missing-alt" ||
      id === "a11y-inputs-unlabelled" ||
      id === "a11y-duplicate-ids" ||
      id === "sec-mixed-content");

  if (isDirectHeader || isDirectDom) {
    return {
      tier: "direct",
      confidence: "high",
      state: state === "observation" ? "confirmed" : state,
      severity,
      rationale: "Condition verified by direct, unambiguous protocol or AST inspection.",
    };
  }

  // 3. Strong structural inference check (cross-referenced elements, SRI external hosts, multiple canonicals)
  const isStructural =
    id === "seo-canonical-multiple" ||
    id === "seo-canonical-missing" ||
    id.startsWith("sec-sri") ||
    id.startsWith("sec-cookie") ||
    id.startsWith("sec-iframe") ||
    id === "a11y-landmarks-missing";

  if (isStructural) {
    return {
      tier: "structural",
      confidence: "high",
      state,
      severity,
      rationale: "Condition inferred from multi-node relational or cross-origin DOM structure.",
    };
  }

  // 4. Heuristic / Advisory / Timing checks (must NOT be presented as certainty)
  const isHeuristic =
    id.startsWith("perf-moderate-ttfb") ||
    id.startsWith("perf-high-ttfb") ||
    id === "perf-payload-truncated" ||
    id === "seo-title-short" ||
    id === "seo-title-long" ||
    id === "seo-meta-description-short" ||
    id === "seo-multiple-h1" ||
    id === "seo-heading-hierarchy-skipped" ||
    id === "seo-opengraph-incomplete" ||
    id === "perf-iframe-lazy-missing" ||
    id === "perf-render-blocking-scripts";

  if (isHeuristic) {
    // If it's an operational limit or latency band, mark as observation or recommendation
    const heuristicState =
      id === "perf-payload-truncated" || id === "perf-moderate-ttfb"
        ? "observation"
        : state === "confirmed"
        ? "recommendation"
        : state;

    return {
      tier: "heuristic",
      confidence: id === "perf-high-ttfb" ? "high" : "medium",
      state: heuristicState,
      severity,
      rationale: "Evaluated via heuristics or operational threshold; advisory rather than strict protocol defect.",
    };
  }

  return {
    tier: "structural",
    confidence: finding.confidence || "medium",
    state,
    severity,
    rationale: "Standard audit inspection rule.",
  };
}

/**
 * Validates that a finding conforms to Phase 7 evidence-quality rules:
 * - Severity reflects impact if true (never probability).
 * - Confidence reflects certainty (high | medium | low).
 * - Unsupported inference cannot become a confirmed finding.
 * - Heuristic evidence is not presented as confirmed certainty.
 */
export function validateEvidenceQuality(finding: Finding): {
  isValid: boolean;
  violations: string[];
} {
  const violations: string[] = [];

  // Severity validity check
  if (!["high", "medium", "low"].includes(finding.severity)) {
    violations.push(`Invalid severity '${finding.severity}'; must be 'high', 'medium', or 'low'.`);
  }

  // Confidence validity check
  if (!["high", "medium", "low"].includes(finding.confidence)) {
    violations.push(`Invalid confidence '${finding.confidence}'; must be 'high', 'medium', or 'low'.`);
  }

  // State validity check
  const validStates = ["confirmed", "observation", "recommendation", "unable_to_check", "not_detected", "failed"];
  if (finding.state && !validStates.includes(finding.state)) {
    violations.push(`Invalid state '${finding.state}'.`);
  }

  const evalResult = classifyEvidenceQuality(finding);

  // Invariant 1: Unsupported inference CANNOT become a confirmed finding
  if (evalResult.tier === "unsupported" && finding.state === "confirmed") {
    violations.push("Unsupported inference cannot become a confirmed finding.");
  }

  // Invariant 2: Heuristic evidence should not be presented as confirmed high-certainty defect
  if (
    evalResult.tier === "heuristic" &&
    finding.state === "confirmed" &&
    (finding.id.startsWith("perf-moderate-ttfb") || finding.id === "perf-payload-truncated")
  ) {
    violations.push(`Heuristic / operational observation '${finding.id}' cannot be marked as confirmed defect.`);
  }

  return {
    isValid: violations.length === 0,
    violations,
  };
}

/**
 * Enforces evidence quality rules on a finding, adjusting state or confidence if misclassified.
 */
export function enforceEvidenceQuality(finding: Finding): Finding {
  const evalResult = classifyEvidenceQuality(finding);

  // If unsupported inference was accidentally marked confirmed, correct it
  if (evalResult.tier === "unsupported" && finding.state === "confirmed") {
    return {
      ...finding,
      state: "unable_to_check",
      confidence: "high",
    };
  }

  // If operational limit was accidentally marked confirmed, correct to observation
  if (
    evalResult.tier === "heuristic" &&
    (finding.id === "perf-payload-truncated" || finding.id === "perf-moderate-ttfb")
  ) {
    return {
      ...finding,
      state: "observation",
      confidence: evalResult.confidence,
    };
  }

  return finding;
}

/**
 * Asserts that all findings in an audit run comply with Phase 7 evidence-quality rules.
 */
export function assertEvidenceQualityAudit(findings: Finding[]): {
  allValid: boolean;
  violationsCount: number;
  report: Record<string, string[]>;
} {
  const report: Record<string, string[]> = {};
  let violationsCount = 0;

  for (const finding of findings) {
    const res = validateEvidenceQuality(finding);
    if (!res.isValid) {
      violationsCount++;
      report[finding.id] = res.violations;
    }
  }

  return {
    allValid: violationsCount === 0,
    violationsCount,
    report,
  };
}
