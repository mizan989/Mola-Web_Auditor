"use client";

import React from "react";
import { CheckCircle2, AlertCircle, RefreshCw, HelpCircle } from "lucide-react";
import { VerificationComparison } from "@/types/audit";

interface VerificationSectionProps {
  comparison: VerificationComparison;
}

/**
 * Fix Verification component conforming to ISSUE-025, ISSUE-050, and Phase 11.
 * Clearly segregates and presents Fixed, Still Present, Changed, New, and Unable to Verify findings.
 */
export function VerificationSection({ comparison }: VerificationSectionProps) {
  const prevTime = new Date(comparison.previousScanTimestamp).toLocaleTimeString();
  const unableCount = comparison.unableToVerifyFindings?.length || 0;

  return (
    <section
      aria-label="Fix Verification Results"
      className="mb-8 p-6 sm:p-7 rounded-2xl border-2 border-[var(--border)] bg-white/40 backdrop-blur-md shadow-sm animate-in fade-in"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 pb-4 border-b border-[var(--border)]">
        <div className="flex items-center gap-2.5">
          <CheckCircle2 className="w-5 h-5 text-[var(--success)] shrink-0" />
          <div>
            <h3 className="font-extrabold text-base text-[var(--dark)]">
              Fix Verification Comparison
            </h3>
            <p className="text-xs text-[var(--muted)] font-mono">
              Target: {comparison.targetUrl} (Baseline from {prevTime})
            </p>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div
        className={`grid ${
          unableCount > 0
            ? "grid-cols-2 sm:grid-cols-5"
            : "grid-cols-2 sm:grid-cols-4"
        } gap-3 text-center mb-6`}
      >
        <div className="p-3.5 rounded-xl bg-white/60 border border-[var(--border)] shadow-2xs">
          <div className="text-2xl sm:text-3xl font-black text-[var(--success)]">
            {comparison.resolvedFindings.length}
          </div>
          <div className="text-[11px] font-extrabold uppercase tracking-wider text-[var(--muted)] mt-0.5">
            Fixed
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-white/60 border border-[var(--border)] shadow-2xs">
          <div className="text-2xl sm:text-3xl font-black text-[var(--warning)]">
            {comparison.remainingFindings.length}
          </div>
          <div className="text-[11px] font-extrabold uppercase tracking-wider text-[var(--muted)] mt-0.5">
            Still Present
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-white/60 border border-[var(--border)] shadow-2xs">
          <div className="text-2xl sm:text-3xl font-black text-[var(--deep)]">
            {comparison.changedFindings.length}
          </div>
          <div className="text-[11px] font-extrabold uppercase tracking-wider text-[var(--muted)] mt-0.5">
            Changed
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-white/60 border border-[var(--border)] shadow-2xs">
          <div className="text-2xl sm:text-3xl font-black text-[var(--error)]">
            {comparison.newFindings.length}
          </div>
          <div className="text-[11px] font-extrabold uppercase tracking-wider text-[var(--muted)] mt-0.5">
            New Issues
          </div>
        </div>

        {unableCount > 0 && (
          <div className="p-3.5 rounded-xl bg-white/60 border border-[var(--border)] shadow-2xs col-span-2 sm:col-span-1">
            <div className="text-2xl sm:text-3xl font-black text-gray-500">
              {unableCount}
            </div>
            <div className="text-[11px] font-extrabold uppercase tracking-wider text-[var(--muted)] mt-0.5">
              Unable to Verify
            </div>
          </div>
        )}
      </div>

      {/* Detailed Diff Sections */}
      <div className="space-y-3 text-xs">
        {comparison.resolvedFindings.length > 0 && (
          <div className="p-4 rounded-xl bg-[var(--success-bg)]/60 border border-[var(--success)]/30">
            <h4 className="font-bold text-[var(--success)] flex items-center gap-1.5 mb-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Resolved Issues ({comparison.resolvedFindings.length})</span>
            </h4>
            <ul className="space-y-1 text-[var(--text-primary)] list-disc list-inside">
              {comparison.resolvedFindings.map((f) => (
                <li key={f.id}>
                  <span className="font-semibold">{f.title}</span> — verified resolved
                </li>
              ))}
            </ul>
          </div>
        )}

        {comparison.changedFindings.length > 0 && (
          <div className="p-4 rounded-xl bg-blue-50/50 border border-blue-200">
            <h4 className="font-bold text-[var(--deep)] flex items-center gap-1.5 mb-2">
              <RefreshCw className="w-4 h-4" />
              <span>Changed Findings ({comparison.changedFindings.length})</span>
            </h4>
            <ul className="space-y-1 text-[var(--text-primary)] list-disc list-inside">
              {comparison.changedFindings.map((f) => {
                const diff = comparison.diffs?.find((d) => d.findingId === f.id);
                let note = `status or severity updated to ${f.severity.toUpperCase()}`;
                if (diff?.changes?.severity) {
                  note = `severity changed from ${diff.changes.severity.from} to ${diff.changes.severity.to}`;
                } else if (diff?.changes?.materialDetails) {
                  note = diff.changes.materialDetails;
                }
                return (
                  <li key={f.id}>
                    <span className="font-semibold">{f.title}</span> — {note}
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {comparison.newFindings.length > 0 && (
          <div className="p-4 rounded-xl bg-[var(--error-bg)]/60 border border-[var(--error)]/30">
            <h4 className="font-bold text-[var(--error)] flex items-center gap-1.5 mb-2">
              <AlertCircle className="w-4 h-4" />
              <span>New Issues Introduced ({comparison.newFindings.length})</span>
            </h4>
            <ul className="space-y-1 text-[var(--text-primary)] list-disc list-inside">
              {comparison.newFindings.map((f) => (
                <li key={f.id}>
                  <span className="font-semibold">{f.title}</span> ({f.severity.toUpperCase()})
                </li>
              ))}
            </ul>
          </div>
        )}

        {unableCount > 0 && comparison.unableToVerifyFindings && (
          <div className="p-4 rounded-xl bg-gray-50 border border-gray-200">
            <h4 className="font-bold text-gray-700 flex items-center gap-1.5 mb-2">
              <HelpCircle className="w-4 h-4" />
              <span>Unable to Verify ({unableCount})</span>
            </h4>
            <ul className="space-y-1 text-gray-700 list-disc list-inside">
              {comparison.unableToVerifyFindings.map((f) => {
                const diff = comparison.diffs?.find((d) => d.findingId === f.id);
                return (
                  <li key={f.id}>
                    <span className="font-semibold">{f.title}</span>
                    {diff?.reason ? ` — ${diff.reason}` : " — relevant check could not be performed"}
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}
