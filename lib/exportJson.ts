import type { ScanResult } from "@/types/audit";

/**
 * Generates an authoritative, lossless JSON export preserving the complete
 * 6-question traceable evidence for every finding.
 */
export function generateAuditJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Parses and returns an exported JSON audit report.
 */
export function parseAuditJson(jsonStr: string): ScanResult {
  return JSON.parse(jsonStr) as ScanResult;
}

export function downloadJsonFile(result: ScanResult) {
  const jsonStr = generateAuditJson(result);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `mola-audit-${result.hostname}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function downloadMarkdownFile(markdownText: string, hostname: string) {
  const blob = new Blob([markdownText], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `issues-${hostname}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
