import type { ScanResult, VerificationComparison } from "../types/audit.ts";

/**
 * Generates an actionable `issues.md` document from audit findings,
 * formatted specifically for AI agents (Gemini, Claude, Cursor) and developer issue tracking.
 * Complies with PRD.md F-008 and issues.md.
 */
export function generateIssuesMarkdown(result: ScanResult): string {
  const {
    targetUrl,
    finalUrl,
    hostname,
    scanTimestamp,
    scanMode,
    completeness,
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
    md += `> - Final Destination: \`${finalUrl}\`\n`;
  }
  md += `> - Scanned: ${dateStr}\n`;
  md += `> - Mode: ${scanMode.toUpperCase()} Scan (${completeness === "full" ? "Complete" : "Partial"})\n`;
  md += `> - Total Findings: **${summary.totalFindings}** (High: ${summary.highCount}, Medium: ${summary.mediumCount}, Low: ${summary.lowCount})\n`;
  if (summary.confidenceCounts) {
    md += `> - Confidence: High: ${summary.confidenceCounts.high}, Medium: ${summary.confidenceCounts.medium}, Low: ${summary.confidenceCounts.low}\n`;
  }
  if (summary.stateCounts) {
    const nonConfirmed = Object.entries(summary.stateCounts)
      .filter(([k, v]) => k !== "confirmed" && v > 0)
      .map(([k, v]) => `${k}: ${v}`)
      .join(", ");
    if (nonConfirmed) {
      md += `> - Finding States: ${nonConfirmed}\n`;
    }
  }
  md += `> - Passed Checks: **${summary.passedCount}**\n\n`;

  // Technologies
  if (technologies.length > 0) {
    md += `## Detected Technology Stack\n\n`;
    md += `| Category | Technology | Confidence | Evidence |\n`;
    md += `|---|---|---|---|\n`;
    for (const tech of technologies) {
      md += `| ${tech.category} | ${tech.name}${tech.version ? ` (${tech.version})` : ""} | ${tech.confidence}% | ${tech.evidence || "Signature matched"} |\n`;
    }
    md += `\n`;
  }

  // HTTP Telemetry
  if (httpInfo) {
    md += `## HTTP & Infrastructure Details\n\n`;
    if (httpInfo.statusCode !== undefined) md += `- **Status**: \`${httpInfo.statusCode} ${httpInfo.statusText || ""}\`\n`;
    if (httpInfo.protocol) md += `- **Protocol**: \`${httpInfo.protocol}\`\n`;
    if (httpInfo.responseTimeMs !== undefined) md += `- **Latency (TTFB)**: \`${httpInfo.responseTimeMs} ms\`\n`;
    if (httpInfo.contentLength !== undefined) {
      md += `- **Payload Size**: \`${Math.round((httpInfo.contentLength / 1024) * 10) / 10} KB\`${httpInfo.isTruncated ? " *(Payload truncated at inspection limit)*" : ""}\n`;
    }
    if (httpInfo.isHttps !== undefined) md += `- **HTTPS Secured**: \`${httpInfo.isHttps ? "Yes" : "No"}\`\n`;
    if (httpInfo.redirectChain && httpInfo.redirectChain.length > 1) {
      md += `- **Redirect Chain**:\n`;
      for (let i = 0; i < httpInfo.redirectChain.length; i++) {
        md += `  ${i + 1}. \`${httpInfo.redirectChain[i]}\`\n`;
      }
    }
    md += `\n`;
  }

  // Reconnaissance Surface Map (Phase 3)
  if (result.reconnaissance) {
    const recon = result.reconnaissance;
    md += `## Target Reconnaissance & Surface Map\n\n`;
    md += `- **Host & Scheme**: \`${recon.target.scheme.toUpperCase()}\` on \`${recon.target.hostname}:${recon.target.port}\`\n`;
    if (recon.target.ipAddresses && recon.target.ipAddresses.length > 0) {
      md += `- **Resolved Addresses**: \`${recon.target.ipAddresses.join(", ")}\`\n`;
    }
    md += `- **Payload Size**: \`${recon.bodyMetadata.byteLength} bytes\` (${recon.bodyMetadata.characterLength} chars)${recon.bodyMetadata.isTruncated ? " *(Truncated at 2.5 MB limit)*" : ""}\n`;
    if (recon.bodyMetadata.charset) {
      md += `- **Encoding / Charset**: \`${recon.bodyMetadata.charset}\`\n`;
    }
    md += `- **Discovered Subresources**: Scripts: ${recon.discoveredResources.scripts.length}, Stylesheets: ${recon.discoveredResources.stylesheets.length}, Images: ${recon.discoveredResources.images.length}, Iframes: ${recon.discoveredResources.iframes.length}\n`;

    if (recon.securityObservations.length > 0) {
      md += `\n**Security Observations & Signals:**\n`;
      for (const obs of recon.securityObservations) {
        md += `- [${obs.provenance.toUpperCase()}] ${obs.observation}\n`;
      }
    }
    md += `\n`;
  }

  // Findings
  md += `## Prioritized Action Items\n\n`;

  if (findings.length === 0) {
    md += `🎉 **Zero critical findings detected.** All monitored categories passed safe baselines.\n\n`;
  } else {
    findings.forEach((finding, idx) => {
      const sevBadge = finding.severity.toUpperCase();
      const priorityLabel = finding.priority.replace("-", " ").toUpperCase();
      const stateBadge = (finding.state || "confirmed").toUpperCase();
      const confidenceBadge = (finding.confidence || "high").toUpperCase();

      md += `### ${idx + 1}. [${sevBadge}] ${finding.title}\n\n`;
      md += `- **State**: \`${stateBadge}\`\n`;
      md += `- **Confidence**: \`${confidenceBadge}\`\n`;
      md += `- **Category**: \`${finding.category}\`\n`;
      md += `- **Priority**: \`${priorityLabel}\`\n`;
      if (finding.affectedTarget) {
        md += `- **Affected Target**: \`${finding.affectedTarget}\`\n`;
      }
      md += `- **Description**: ${finding.description}\n`;
      md += `- **Why It Matters**: ${finding.whyItMatters}\n\n`;

      md += `**Concrete Evidence:**\n\`\`\`text\n${finding.evidence}\n\`\`\`\n\n`;

      if (finding.structuredEvidence) {
        const se = finding.structuredEvidence;
        md += `**Structured Evidence:**\n`;
        if (se.observation) md += `- **Observation**: ${se.observation}\n`;
        if (se.expectedCondition) md += `- **Expected**: ${se.expectedCondition}\n`;
        if (se.evidenceType) md += `- **Evidence Type**: \`${se.evidenceType}\`\n`;
        if (se.sourceUrl) md += `- **Source URL**: \`${se.sourceUrl}\`\n`;
        if (se.affectedTarget) md += `- **Target**: \`${se.affectedTarget}\`\n`;
        if (se.limitations) md += `- **Limitations**: ${se.limitations}\n`;
        md += `\n`;
      } else if (finding.limitations) {
        md += `**Limitations:** ${finding.limitations}\n\n`;
      }

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
      const stateBadge = check.state && check.state !== "confirmed" ? ` [${check.state.toUpperCase()}]` : "";
      md += `- [x] **[${check.category}]**${stateBadge} ${check.title}: ${check.detail}\n`;
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
  md += `- 🟢 Resolved (Fixed): **${comparison.resolvedFindings.length}**\n`;
  md += `- 🟡 Still Present: **${comparison.remainingFindings.length}**\n`;
  md += `- 🔵 Changed Status: **${comparison.changedFindings.length}**\n`;
  md += `- 🔴 New Issues Detected: **${comparison.newFindings.length}**\n\n`;

  if (comparison.resolvedFindings.length > 0) {
    md += `### 🟢 Resolved Issues (Fixed)\n`;
    for (const f of comparison.resolvedFindings) {
      md += `- [x] **[${f.severity.toUpperCase()}]** ${f.title}\n`;
    }
    md += `\n`;
  }

  if (comparison.remainingFindings.length > 0) {
    md += `### 🟡 Still Present\n`;
    for (const f of comparison.remainingFindings) {
      md += `- [ ] **[${f.severity.toUpperCase()}]** ${f.title}\n`;
    }
    md += `\n`;
  }

  if (comparison.changedFindings.length > 0) {
    md += `### 🔵 Changed Status\n`;
    for (const f of comparison.changedFindings) {
      md += `- [ ] **[${f.severity.toUpperCase()}]** ${f.title} *(Severity/details updated)*\n`;
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
