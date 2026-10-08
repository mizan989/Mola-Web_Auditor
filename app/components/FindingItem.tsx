"use client";

import React from "react";
import { ChevronDown, ChevronUp, ShieldAlert, AlertTriangle, Info } from "lucide-react";
import { Finding } from "@/types/audit";

interface FindingItemProps {
  finding: Finding;
  isExpanded: boolean;
  onToggleExpand: () => void;
}

/**
 * Finding card item conforming to ISSUE-046 (ordered readability:
 * 1. Severity/status, 2. Title, 3. Explanation, 4. Evidence, 5. Why it matters, 6. Recommendation)
 * and ISSUE-047 (communicates severity via visible text and accessible labels, not color alone).
 */
export function FindingItem({ finding, isExpanded, onToggleExpand }: FindingItemProps) {
  const severityBorder =
    finding.severity === "high"
      ? "border-l-[var(--error)]"
      : finding.severity === "medium"
      ? "border-l-[var(--warning)]"
      : "border-l-[var(--success)]";

  const SeverityIcon =
    finding.severity === "high"
      ? ShieldAlert
      : finding.severity === "medium"
      ? AlertTriangle
      : Info;

  const severityBadgeClass =
    finding.severity === "high"
      ? "bg-[var(--error-bg)] text-[var(--error)] border-[var(--error)]/30"
      : finding.severity === "medium"
      ? "bg-[var(--warning-bg)] text-[var(--warning)] border-[var(--warning)]/30"
      : "bg-[var(--success-bg)] text-[var(--success)] border-[var(--success)]/30";

  return (
    <article
      className={`p-5 sm:p-6 rounded-2xl border border-[var(--border)] border-l-4 ${severityBorder} bg-white/45 backdrop-blur-xs transition-all shadow-xs`}
      aria-labelledby={`finding-title-${finding.id}`}
    >
      {/* 1. Header with Severity/Status & Title & Explanation */}
      <div
        className="flex items-start justify-between gap-4 cursor-pointer select-none rounded-xl p-1 -m-1 outline-none focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
        onClick={onToggleExpand}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggleExpand();
          }
        }}
        aria-expanded={isExpanded}
      >
        <div className="flex-1">
          {/* 1. Severity / Status (ISSUE-047: Visible text + icon + accessible label) */}
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-extrabold uppercase tracking-wider text-[var(--muted)] mb-1.5">
            <span
              className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md border font-black ${severityBadgeClass}`}
              aria-label={`Severity: ${finding.severity.toUpperCase()}`}
            >
              <SeverityIcon className="w-3 h-3" />
              <span>{finding.severity.toUpperCase()}</span>
            </span>
            {finding.confidence && (
              <span
                className="px-2 py-0.5 rounded-md border border-[var(--border)] bg-black/5 text-[var(--dark)] font-bold"
                aria-label={`Confidence: ${finding.confidence.toUpperCase()}`}
              >
                {finding.confidence.toUpperCase()} CONFIDENCE
              </span>
            )}
            {finding.state === "observation" ? (
              <span
                className="px-2 py-0.5 rounded-md border border-blue-500/30 bg-blue-500/10 text-blue-700 font-bold"
                aria-label="State: Uncertain Observation"
              >
                OBSERVATION
              </span>
            ) : finding.state && finding.state !== "confirmed" ? (
              <span
                className="px-2 py-0.5 rounded-md border border-[var(--border)] bg-amber-500/10 text-amber-700 font-bold"
                aria-label={`State: ${finding.state}`}
              >
                {finding.state.replace("_", " ").toUpperCase()}
              </span>
            ) : null}
            <span>·</span>
            <span className="font-bold text-[var(--dark)]">{finding.category.toUpperCase()}</span>
            <span>·</span>
            <span className="text-[var(--muted)]">{finding.priority.replace("-", " ").toUpperCase()}</span>
          </div>

          {/* 2. Finding Title */}
          <h3 id={`finding-title-${finding.id}`} className="text-base sm:text-lg font-bold text-[var(--dark)]">
            {finding.title}
          </h3>

          {/* 3. Short Explanation (Description) */}
          <p className="text-xs sm:text-sm text-[var(--muted)] mt-1.5 leading-relaxed">
            {finding.description}
          </p>
        </div>

        <span
          aria-hidden="true"
          className="p-1.5 rounded-lg text-[var(--muted)] shrink-0"
        >
          {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </span>
      </div>

      {/* Expandable Details Container (ISSUE-046 order) */}
      {isExpanded && (
        <div className="mt-5 pt-4 border-t border-[var(--border)] space-y-4 text-xs text-[var(--text-primary)] animate-in fade-in">
          {/* 4. Concrete Evidence (ISSUE-046 #4 & ISSUE-029) */}
          <div>
            <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
              Concrete Evidence
            </span>
            <pre className="p-3.5 rounded-xl bg-[var(--dark)] text-[var(--white)] font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
              {finding.evidence}
            </pre>
          </div>

          {/* Structured Evidence Details */}
          {finding.structuredEvidence && (
            <div className="p-3 rounded-xl bg-black/5 border border-[var(--border)] space-y-1.5 text-xs">
              <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block">
                Evidence Details
              </span>
              {finding.structuredEvidence.expectedCondition && (
                <div className="text-[11px]">
                  <span className="font-semibold text-[var(--dark)]">Expected: </span>
                  <span className="text-[var(--text-primary)]">{finding.structuredEvidence.expectedCondition}</span>
                </div>
              )}
              {finding.structuredEvidence.evidenceType && (
                <div className="text-[11px]">
                  <span className="font-semibold text-[var(--dark)]">Type: </span>
                  <code className="text-[var(--muted)]">{finding.structuredEvidence.evidenceType}</code>
                </div>
              )}
              {finding.structuredEvidence.limitations && (
                <div className="text-[11px] text-amber-800">
                  <span className="font-semibold">Limitation: </span>
                  <span>{finding.structuredEvidence.limitations}</span>
                </div>
              )}
            </div>
          )}

          {finding.limitations && !finding.structuredEvidence?.limitations && (
            <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-[11px]">
              <span className="font-semibold">Limitation: </span>
              <span>{finding.limitations}</span>
            </div>
          )}

          {/* Affected Target Resource */}
          {finding.affectedTarget && (
            <div>
              <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
                Affected Resource
              </span>
              <code className="px-2 py-1 rounded bg-white/70 border border-[var(--border)] font-mono text-[11px] text-[var(--dark)]">
                {finding.affectedTarget}
              </code>
            </div>
          )}

          {/* 5. Why It Matters (ISSUE-046 #5) */}
          <div>
            <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
              Why it matters
            </span>
            <p className="text-[var(--text-primary)] leading-relaxed">
              {finding.whyItMatters}
            </p>
          </div>

          {/* 6. Recommendation (ISSUE-046 #6) */}
          <div>
            <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
              Recommended Fix
            </span>
            <p className="text-[var(--dark)] font-medium mb-2 leading-relaxed">
              {finding.recommendation}
            </p>
            {finding.codeSnippet && (
              <pre className="p-3.5 rounded-xl bg-[var(--deep)] text-[var(--white)] font-mono text-xs overflow-x-auto">
                <code>{finding.codeSnippet}</code>
              </pre>
            )}
          </div>
        </div>
      )}
    </article>
  );
}
