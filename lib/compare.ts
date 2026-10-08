import type {
  Finding,
  ScanResult,
  VerificationComparison,
  VerificationFindingDiff,
} from "../types/audit.ts";

/**
 * Normalizes an affected target string for deterministic comparison.
 */
function normalizeTarget(target?: string): string {
  if (!target) return "";
  let t = target.trim().toLowerCase();
  if (t.startsWith("http://") || t.startsWith("https://")) {
    t = t.replace(/\/+$/, "");
  }
  return t;
}

/**
 * Derives a stable semantic key for a finding across scans (ISSUE-025, Phase 11).
 * Uses category, rule ID, and normalized affectedTarget so findings are compared by substance,
 * not transient random IDs.
 */
export function getStableFindingKey(finding: Finding): string {
  const target = normalizeTarget(finding.affectedTarget);
  return `${finding.category}::${finding.id}::${target}`;
}

/**
 * Checks whether a finding originates from or requires Deep Scan / isolated browser inspection.
 */
export function isDeepOrBrowserCheck(finding: Finding): boolean {
  if (
    finding.id.startsWith("browser-") ||
    finding.id.startsWith("sec-browser-") ||
    finding.id.startsWith("a11y-rendered-") ||
    finding.id.startsWith("sec-sri-") ||
    finding.id.startsWith("sec-cookie-session-")
  ) {
    return true;
  }
  if (finding.structuredEvidence?.evidenceType?.startsWith("browser-")) {
    return true;
  }
  return false;
}

/**
 * Determines whether the check corresponding to a previously observed finding
 * could actually be executed during the rescan.
 *
 * CRITICAL RULE (Phase 11):
 * A finding must not be called fixed merely because it disappeared if the relevant check could not run.
 */
export function canCheckRunInRescan(
  prevFinding: Finding,
  previousResult: ScanResult,
  newResult: ScanResult
): { canRun: boolean; reason?: string } {
  // 1. Overall rescan failure or unreachable target
  if (newResult.status === "failed") {
    return {
      canRun: false,
      reason: "Verification rescan failed before checks could be executed.",
    };
  }

  if (newResult.httpInfo?.statusCode === 0) {
    return {
      canRun: false,
      reason: "Target was unreachable (status code 0) during verification rescan.",
    };
  }

  if (
    newResult.findings.some(
      (f) => f.id === "http-connection-failed" && f.state === "unable_to_check"
    )
  ) {
    return {
      canRun: false,
      reason: "HTTP connection failed during verification rescan.",
    };
  }

  // 2. Scan Mode Downgrade (Deep Scan -> Quick Scan)
  const isDeepCheck = isDeepOrBrowserCheck(prevFinding);
  if (previousResult.scanMode === "deep" && newResult.scanMode === "quick" && isDeepCheck) {
    return {
      canRun: false,
      reason:
        "Finding was detected during Deep Scan, but verification rescan was run in Quick Scan mode. Deep checks were not performed.",
    };
  }

  // 3. Browser execution unavailable or aborted for browser-based findings
  const isBrowserFinding =
    prevFinding.id.startsWith("browser-") ||
    prevFinding.id.startsWith("sec-browser-") ||
    prevFinding.id.startsWith("a11y-rendered-") ||
    prevFinding.structuredEvidence?.evidenceType?.startsWith("browser-");

  if (isBrowserFinding) {
    if (!newResult.browserExecution || !newResult.browserExecution.executed) {
      const limitation =
        newResult.browserExecution?.limitationReason ||
        "Isolated browser execution was unconfigured or did not run during verification rescan.";
      return {
        canRun: false,
        reason: limitation,
      };
    }
  }

  // 4. Relevant scanner module reported unable_to_check in the new scan
  const moduleCheckFailed = newResult.findings.find(
    (f) => f.category === prevFinding.category && f.state === "unable_to_check"
  );
  if (
    moduleCheckFailed &&
    !newResult.passedChecks.some((p) => p.category === prevFinding.category)
  ) {
    return {
      canRun: false,
      reason: `Module '${prevFinding.category}' reported incomplete checks: ${moduleCheckFailed.description}`,
    };
  }

  return { canRun: true };
}

/**
 * Detects material changes between an existing finding and its rescan counterpart.
 * Compares: state, severity, priority, confidence, evidence, affected resource,
 * material details (instances count), and recommendations.
 */
export function detectFindingChanges(
  prev: Finding,
  curr: Finding
): {
  hasMaterialChange: boolean;
  changes: NonNullable<VerificationFindingDiff["changes"]>;
} {
  const changes: NonNullable<VerificationFindingDiff["changes"]> = {};
  let hasMaterialChange = false;

  if (curr.severity !== prev.severity) {
    changes.severity = { from: prev.severity, to: curr.severity };
    hasMaterialChange = true;
  }

  if (curr.priority !== prev.priority) {
    changes.priority = { from: prev.priority, to: curr.priority };
    hasMaterialChange = true;
  }

  if (curr.state !== prev.state) {
    changes.state = { from: prev.state, to: curr.state };
    hasMaterialChange = true;
  }

  if (curr.confidence !== prev.confidence) {
    changes.confidence = { from: prev.confidence, to: curr.confidence };
    hasMaterialChange = true;
  }

  if (normalizeTarget(curr.affectedTarget) !== normalizeTarget(prev.affectedTarget)) {
    changes.affectedTarget = {
      from: prev.affectedTarget || "",
      to: curr.affectedTarget || "",
    };
    hasMaterialChange = true;
  }

  if (curr.evidence !== prev.evidence) {
    changes.evidence = { from: prev.evidence, to: curr.evidence };
    hasMaterialChange = true;
  }

  if (curr.recommendation !== prev.recommendation) {
    changes.recommendation = { from: prev.recommendation, to: curr.recommendation };
    hasMaterialChange = true;
  }

  if (
    curr.instancesCount !== undefined &&
    prev.instancesCount !== undefined &&
    curr.instancesCount !== prev.instancesCount
  ) {
    changes.instancesCount = {
      from: prev.instancesCount,
      to: curr.instancesCount,
    };
    changes.materialDetails = `Instance count changed from ${prev.instancesCount} to ${curr.instancesCount}`;
    hasMaterialChange = true;
  }

  return { hasMaterialChange, changes };
}

/**
 * Compares two audit results for the Fix Verification loop (Phase 11).
 * Classifies findings into:
 * - fixed (resolved)
 * - still_present (persists unchanged)
 * - changed (severity, state, confidence, evidence, recommendation, or instances count modified)
 * - new (newly introduced finding)
 * - unable_to_verify (check could not be performed during rescan)
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
  const unableToVerifyFindings: Finding[] = [];
  const diffs: VerificationFindingDiff[] = [];

  // Inspect all findings that existed in the previous scan
  for (const [key, prevFinding] of previousMap.entries()) {
    const currentFinding = currentMap.get(key);

    if (!currentFinding) {
      // Existed previously, absent in current scan.
      // Must verify that the check could actually execute!
      const checkRunability = canCheckRunInRescan(prevFinding, previousResult, newResult);

      if (!checkRunability.canRun) {
        // Relevant check could not be run; cannot mark fixed!
        unableToVerifyFindings.push(prevFinding);
        diffs.push({
          findingId: prevFinding.id,
          category: prevFinding.category,
          title: prevFinding.title,
          status: "unable_to_verify",
          affectedTarget: prevFinding.affectedTarget || "",
          previousFinding: prevFinding,
          reason: checkRunability.reason,
        });
      } else {
        // Check executed cleanly and confirmed the finding is gone -> Fixed
        resolvedFindings.push(prevFinding);
        diffs.push({
          findingId: prevFinding.id,
          category: prevFinding.category,
          title: prevFinding.title,
          status: "fixed",
          affectedTarget: prevFinding.affectedTarget || "",
          previousFinding: prevFinding,
        });
      }
    } else {
      // Existed previously and still reported in current scan
      if (currentFinding.state === "unable_to_check") {
        unableToVerifyFindings.push(currentFinding);
        diffs.push({
          findingId: currentFinding.id,
          category: currentFinding.category,
          title: currentFinding.title,
          status: "unable_to_verify",
          affectedTarget: currentFinding.affectedTarget || "",
          previousFinding: prevFinding,
          currentFinding,
          reason: "Rescan produced an unable_to_check outcome.",
        });
      } else {
        const { hasMaterialChange, changes } = detectFindingChanges(
          prevFinding,
          currentFinding
        );

        if (hasMaterialChange) {
          changedFindings.push(currentFinding);
          diffs.push({
            findingId: currentFinding.id,
            category: currentFinding.category,
            title: currentFinding.title,
            status: "changed",
            affectedTarget: currentFinding.affectedTarget || "",
            previousFinding: prevFinding,
            currentFinding,
            changes,
          });
        } else {
          remainingFindings.push(currentFinding);
          diffs.push({
            findingId: currentFinding.id,
            category: currentFinding.category,
            title: currentFinding.title,
            status: "still_present",
            affectedTarget: currentFinding.affectedTarget || "",
            previousFinding: prevFinding,
            currentFinding,
          });
        }
      }
    }
  }

  // Inspect all findings in the current scan for newly introduced issues
  for (const [key, currentFinding] of currentMap.entries()) {
    if (!previousMap.has(key)) {
      newFindings.push(currentFinding);
      diffs.push({
        findingId: currentFinding.id,
        category: currentFinding.category,
        title: currentFinding.title,
        status: "new",
        affectedTarget: currentFinding.affectedTarget || "",
        currentFinding,
      });
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
    unableToVerifyFindings,
    diffs,
    totalPrevious: previousResult.findings.length,
    totalCurrent: newResult.findings.length,
    summary: {
      fixed: resolvedFindings.length,
      stillPresent: remainingFindings.length,
      changed: changedFindings.length,
      new: newFindings.length,
      unableToVerify: unableToVerifyFindings.length,
    },
  };
}
