import {
  ScanResult,
  VerificationComparison,
} from "@/types/audit";

/**
 * Compares two audit results for the Fix Verification loop (PRD.md F-017).
 * Pure client/server-safe utility with zero Node.js dependencies.
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
