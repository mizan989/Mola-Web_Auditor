/**
 * Phase 9: Finding Deduplication and Semantic Correlation Engine.
 *
 * Implements deterministic semantic correlation keys based on:
 * - category
 * - rule/check ID
 * - affected target/resource
 * - relevant condition
 *
 * Merges true duplicates while strictly preserving supporting evidence.
 * Does not merge merely because titles resemble each other.
 */

import type {
  Finding,
  FindingSeverity,
  FindingConfidence,
  FindingPriority,
  FindingState,
} from "../types/audit.ts";

export interface CorrelationKeyComponents {
  category: string;
  ruleId: string;
  affectedTarget: string;
  condition: string;
}

const severityWeight: Record<FindingSeverity, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

const confidenceWeight: Record<FindingConfidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

const priorityWeight: Record<FindingPriority, number> = {
  critical: 4,
  "fix-first": 3,
  recommended: 2,
  investigate: 1,
};

/**
 * Normalizes an affected target string (stripping protocol whitespace, trailing slashes on URLs).
 */
export function normalizeTarget(target?: string): string {
  if (!target) return "";
  const trimmed = target.trim().toLowerCase();
  try {
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      const u = new URL(trimmed);
      return `${u.protocol}//${u.host}${u.pathname}`.replace(/\/+$/, "");
    }
  } catch {
    // Non-URL targets like "<head>", "HTTP Response Headers", etc.
  }
  return trimmed;
}

/**
 * Normalizes the relevant condition descriptor for a finding.
 * Uses structured expected condition, evidence type, or fallback to rule definition.
 */
export function normalizeCondition(finding: Finding): string {
  const cond =
    finding.structuredEvidence?.expectedCondition ||
    finding.structuredEvidence?.evidenceType ||
    finding.title ||
    "";
  return cond.trim().toLowerCase();
}

/**
 * Extracts correlation key components from a finding.
 */
export function extractCorrelationComponents(finding: Finding): CorrelationKeyComponents {
  const category = (finding.category || "").trim().toLowerCase();
  const ruleId = (finding.id || "").trim().toLowerCase();
  const affectedTarget = normalizeTarget(finding.affectedTarget || finding.structuredEvidence?.affectedTarget);
  const condition = normalizeCondition(finding);

  return { category, ruleId, affectedTarget, condition };
}

/**
 * Generates a deterministic semantic correlation key for a finding.
 * Format: `${category}::${ruleId}::${affectedTarget}::${condition}`
 */
export function generateCorrelationKey(finding: Finding): string {
  const { category, ruleId, affectedTarget, condition } = extractCorrelationComponents(finding);
  return `${category}::${ruleId}::${affectedTarget}::${condition}`;
}

/**
 * Evaluates whether two findings are semantic true duplicates.
 * They are duplicates IF AND ONLY IF category, ruleId, affectedTarget, and condition match.
 */
export function isSemanticDuplicate(a: Finding, b: Finding): boolean {
  return generateCorrelationKey(a) === generateCorrelationKey(b);
}

/**
 * Merges two true duplicate findings, rigorously preserving all supporting evidence,
 * instance locations, and selecting the most conservative severity and highest confidence.
 */
export function mergeDuplicateFindings(primary: Finding, duplicate: Finding): Finding {
  // Determine highest severity
  const severity: FindingSeverity =
    severityWeight[duplicate.severity] > severityWeight[primary.severity]
      ? duplicate.severity
      : primary.severity;

  // Determine highest confidence
  const confidence: FindingConfidence =
    confidenceWeight[duplicate.confidence] > confidenceWeight[primary.confidence]
      ? duplicate.confidence
      : primary.confidence;

  // Determine highest priority
  const priority: FindingPriority =
    priorityWeight[duplicate.priority] > priorityWeight[primary.priority]
      ? duplicate.priority
      : primary.priority;

  // Determine state (confirmed takes precedence over observation/recommendation)
  let state: FindingState = primary.state;
  if (duplicate.state === "confirmed" && primary.state !== "confirmed") {
    state = "confirmed";
  } else if (!state) {
    state = duplicate.state;
  }

  // Merge supporting evidence strings without redundant repetition
  let mergedEvidence = primary.evidence;
  if (duplicate.evidence && !primary.evidence.includes(duplicate.evidence)) {
    mergedEvidence = `${primary.evidence}; ${duplicate.evidence}`;
  }

  // Merge instance occurrences
  const combinedInstances = Array.from(
    new Set([...(primary.instances || []), ...(duplicate.instances || [])])
  );
  const instancesCount =
    combinedInstances.length > 0
      ? combinedInstances.length
      : (primary.instancesCount || 0) + (duplicate.instancesCount || 0);

  // Merge limitations
  const mergedLimitations =
    primary.limitations && duplicate.limitations && !primary.limitations.includes(duplicate.limitations)
      ? `${primary.limitations} ${duplicate.limitations}`
      : primary.limitations || duplicate.limitations;

  // Merge structured evidence
  const mergedStructuredEvidence = primary.structuredEvidence
    ? {
        ...primary.structuredEvidence,
        observation:
          duplicate.structuredEvidence?.observation &&
          !primary.structuredEvidence.observation.includes(duplicate.structuredEvidence.observation)
            ? `${primary.structuredEvidence.observation}; ${duplicate.structuredEvidence.observation}`
            : primary.structuredEvidence.observation,
        metadata: {
          ...(primary.structuredEvidence.metadata || {}),
          ...(duplicate.structuredEvidence?.metadata || {}),
          mergedDuplicateCount:
            ((primary.structuredEvidence.metadata?.mergedDuplicateCount as number) || 1) + 1,
        },
        limitations: mergedLimitations,
      }
    : duplicate.structuredEvidence;

  const key = primary.correlationKey || generateCorrelationKey(primary);

  return {
    ...primary,
    severity,
    confidence,
    priority,
    state,
    evidence: mergedEvidence,
    instances: combinedInstances.length > 0 ? combinedInstances : undefined,
    instancesCount: instancesCount > 0 ? instancesCount : undefined,
    limitations: mergedLimitations,
    structuredEvidence: mergedStructuredEvidence,
    correlationKey: key,
  };
}

/**
 * Deduplicates an array of findings deterministically.
 * Merges true semantic duplicates while leaving unrelated findings separate.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const mergedMap = new Map<string, Finding>();
  const order: string[] = [];

  for (const finding of findings) {
    const key = generateCorrelationKey(finding);
    const findingWithKey: Finding = {
      ...finding,
      correlationKey: key,
    };

    if (mergedMap.has(key)) {
      const existing = mergedMap.get(key)!;
      const merged = mergeDuplicateFindings(existing, findingWithKey);
      mergedMap.set(key, merged);
    } else {
      mergedMap.set(key, findingWithKey);
      order.push(key);
    }
  }

  return order.map((key) => mergedMap.get(key)!);
}

/**
 * Correlates findings into groups by semantic correlation key.
 */
export function correlateFindings(findings: Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();

  for (const finding of findings) {
    const key = generateCorrelationKey(finding);
    const existing = groups.get(key) || [];
    existing.push({ ...finding, correlationKey: key });
    groups.set(key, existing);
  }

  return groups;
}
