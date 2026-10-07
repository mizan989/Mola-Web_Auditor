import type { Finding, ScanResult, VerificationComparison } from "../types/audit.ts";

/**
 * Derives a stable semantic key for a finding across scans (ISSUE-025).
 * Uses category, rule ID, and affectedTarget so findings are compared by substance,
 * not transient random IDs.
 */
function getStableFindingKey(finding: Finding): string {
  const target = (finding.affectedTarget || "").trim().toLowerCase();
  return `${finding.category}::${finding.id}::${target}`;
}

/**
 * Compares two audit results for the Fix Verification loop.
 * Classifies findings as Resolved (Fixed), Remaining (Still Present), Changed, or New.
 * Complies with ISSUE-025 and ISSUE-050.
 */
export function compareAuditResults(
  previousResult: ScanResult,
  newResult: ScanResult
): VerificationComparison {
  const previousMap = new Map<string, Finding>();
  for (const f of previousResult.findings) {
    previousMap.set(getStableFindingKey(f), f);
  }

  const currentMap = new Map<string, Finding>();
  for (const f of newResult.findings) {
    currentMap.set(getStableFindingKey(f), f);
  }

  const resolvedFindings: Finding[] = [];
  const remainingFindings: Finding[] = [];
  const changedFindings: Finding[] = [];
  const newFindings: Finding[] = [];

  // Inspect all findings that existed in the previous scan
  for (const [key, prevFinding] of previousMap.entries()) {
    const currentFinding = currentMap.get(key);

    if (!currentFinding) {
      // Existed previously, no longer detected -> Fixed / Resolved
      resolvedFindings.push(prevFinding);
    } else {
      // Existed previously and still detected
      if (
        currentFinding.severity !== prevFinding.severity ||
        currentFinding.priority !== prevFinding.priority
      ) {
        // Finding status/severity changed
        changedFindings.push(currentFinding);
      } else {
        // Unchanged
        remainingFindings.push(currentFinding);
      }
    }
  }

  // Inspect all findings in the current scan for newly introduced issues
  for (const [key, currentFinding] of currentMap.entries()) {
    if (!previousMap.has(key)) {
      newFindings.push(currentFinding);
    }
  }

  return {
    previousScanTimestamp: previousResult.scanTimestamp,
    newScanTimestamp: newResult.scanTimestamp,
    targetUrl: newResult.targetUrl,
    resolvedFindings,
    remainingFindings,
    changedFindings,
    newFindings,
    totalPrevious: previousResult.findings.length,
    totalCurrent: newResult.findings.length,
  };
}
