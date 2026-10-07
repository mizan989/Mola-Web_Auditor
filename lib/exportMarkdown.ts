import { ScanResult, VerificationComparison } from "@/types/audit";

/**
 * Generates an actionable `issues.md` document from audit findings,
 * formatted specifically for AI agents (Gemini, Claude, Cursor) and developer issue tracking.
 * Complies with PRD.md F-008.
 */
export function generateIssuesMarkdown(result: ScanResult): string {
  const {
    targetUrl,
    finalUrl,
    hostname,
    scanTimestamp,
    scanMode,
    summary,
    findings,
    passedChecks,
    technologies,
    httpInfo,
  } = result;

  const dateStr = new Date(scanTimestamp).toLocaleString("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  });

  let md = `# Audit Issues & Recommendations — ${hostname}\n\n`;
  md += `> **Audit Metadata**\n`;
  md += `> - Target: \`${targetUrl}\`\n`;
  if (finalUrl !== targetUrl) {
    md += `> - Final Redirect: \`${finalUrl}\`\n`;
  }
  md += `> - Scanned: ${dateStr}\n`;
  md += `> - Mode: ${scanMode.toUpperCase()} Scan\n`;
  md += `> - Total Findings: **${summary.totalFindings}** (High: ${summary.highCount}, Medium: ${summary.mediumCount}, Low: ${summary.lowCount})\n`;
  md += `> - Passed Checks: **${summary.passedCount}**\n\n`;

  // Technologies
  if (technologies.length > 0) {
    md += `## Detected Technology Stack\n\n`;
    md += `| Category | Technology | Confidence |\n`;
    md += `|---|---|---|\n`;
    for (const tech of technologies) {
      md += `| ${tech.category} | ${tech.name}${tech.version ? ` (${tech.version})` : ""} | ${tech.confidence}% |\n`;
    }
    md += `\n`;
  }

  // HTTP Telemetry
  md += `## HTTP & Infrastructure Details\n\n`;
  md += `- **Status**: \`${httpInfo.statusCode} ${httpInfo.statusText}\`\n`;
  md += `- **Protocol**: \`${httpInfo.protocol}\`\n`;
  md += `- **Latency (TTFB)**: \`${httpInfo.responseTimeMs} ms\`\n`;
  md += `- **Payload Size**: \`${Math.round((httpInfo.contentLength / 1024) * 10) / 10} KB\`\n`;
  md += `- **HTTPS Secured**: \`${httpInfo.isHttps ? "Yes" : "No"}\`\n\n`;

  // Findings
  md += `## Prioritized Action Items\n\n`;

  if (findings.length === 0) {
    md += `🎉 **Zero critical findings detected.** All monitored categories passed safe baselines.\n\n`;
  } else {
    findings.forEach((finding, idx) => {
      const sevBadge = finding.severity.toUpperCase();
      const priorityLabel = finding.priority.replace("-", " ").toUpperCase();

      md += `### ${idx + 1}. [${sevBadge}] ${finding.title}\n\n`;
      md += `- **Category**: \`${finding.category}\`\n`;
      md += `- **Priority**: \`${priorityLabel}\`\n`;
      if (finding.affectedTarget) {
        md += `- **Affected Target**: \`${finding.affectedTarget}\`\n`;
      }
      md += `- **Description**: ${finding.description}\n`;
      md += `- **Why It Matters**: ${finding.whyItMatters}\n\n`;

      md += `**Concrete Evidence:**\n\`\`\`text\n${finding.evidence}\n\`\`\`\n\n`;

      md += `**Recommended Fix:**\n${finding.recommendation}\n\n`;

      if (finding.codeSnippet) {
        md += `\`\`\`${finding.codeSnippet.includes(";") || finding.codeSnippet.includes(":") ? "nginx" : "html"}\n${finding.codeSnippet}\n\`\`\`\n\n`;
      }

      md += `---\n\n`;
    });
  }

  // Passed Checks Summary
  if (passedChecks.length > 0) {
    md += `## Verified Passing Checks\n\n`;
    for (const check of passedChecks) {
      md += `- [x] **[${check.category}]** ${check.title}: ${check.detail}\n`;
    }
    md += `\n`;
  }

  md += `*Generated automatically by [Mola Web Auditor](https://github.com/mizan989/Mola-Web_Auditor).*`;

  return md;
}

/**
 * Generates verification comparison report in Markdown.
 */
export function generateVerificationMarkdown(comparison: VerificationComparison): string {
  let md = `# Fix Verification Report — ${comparison.targetUrl}\n\n`;
  md += `- Previous Scan: ${comparison.previousScanTimestamp}\n`;
  md += `- Current Scan: ${comparison.newScanTimestamp}\n\n`;

  md += `## Summary\n`;
  md += `- 🟢 Resolved Issues: **${comparison.resolvedFindings.length}**\n`;
  md += `- 🟡 Remaining Issues: **${comparison.remainingFindings.length}**\n`;
  md += `- 🔴 New Issues: **${comparison.newFindings.length}**\n\n`;

  if (comparison.resolvedFindings.length > 0) {
    md += `### 🟢 Resolved Issues\n`;
    for (const f of comparison.resolvedFindings) {
      md += `- [x] **[${f.severity.toUpperCase()}]** ${f.title}\n`;
    }
    md += `\n`;
  }

  if (comparison.remainingFindings.length > 0) {
    md += `### 🟡 Remaining Issues\n`;
    for (const f of comparison.remainingFindings) {
      md += `- [ ] **[${f.severity.toUpperCase()}]** ${f.title}\n`;
    }
    md += `\n`;
  }

  if (comparison.newFindings.length > 0) {
    md += `### 🔴 New Issues Detected\n`;
    for (const f of comparison.newFindings) {
      md += `- [ ] **[${f.severity.toUpperCase()}]** ${f.title}\n`;
    }
    md += `\n`;
  }

  return md;
}
