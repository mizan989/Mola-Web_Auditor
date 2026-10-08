"use client";

import React from "react";
import { Cpu, AlertCircle } from "lucide-react";
import { ScanResult } from "@/types/audit";
import { ExportControls } from "./ExportControls";

interface ReportSummaryProps {
  result: ScanResult;
  isScanning: boolean;
  onRescan: () => void;
}

/**
 * Report summary component conforming to ISSUE-045 (Improved hierarchy without redesign)
 * and ISSUE-028 (Clearly identifies partial audits vs complete audits).
 */
export function ReportSummary({ result, isScanning, onRescan }: ReportSummaryProps) {
  const isRedirected = result.finalUrl !== result.targetUrl;

  return (
    <div className="p-6 sm:p-8 rounded-3xl border border-[var(--border)] bg-white/35 backdrop-blur-md shadow-sm mb-8">
      {/* 1. Target URL, Scan status/mode, Audit completeness */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between pb-6 border-b border-[var(--border)] gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 text-xs font-bold uppercase tracking-wider text-[var(--muted)] mb-1">
            <span className="font-mono text-[var(--dark)] bg-black/5 px-2 py-0.5 rounded">
              {result.scanMode.toUpperCase()} SCAN
            </span>
            <span>·</span>
            <span
              className={`px-2 py-0.5 rounded font-extrabold ${
                result.completeness === "full"
                  ? "bg-[var(--success-bg)] text-[var(--success)]"
                  : "bg-[var(--warning-bg)] text-[var(--warning)]"
              }`}
            >
              {result.completeness === "full" ? "COMPLETE AUDIT" : "PARTIAL AUDIT"}
            </span>
            <span>·</span>
            <span className="font-mono">{new Date(result.scanTimestamp).toLocaleTimeString()}</span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-black tracking-tight text-[var(--dark)] mt-1">
            {result.hostname}
          </h2>

          <div className="text-xs text-[var(--muted)] font-mono mt-1 space-y-0.5">
            <p>Target: {result.targetUrl}</p>
            {isRedirected && (
              <p className="text-[var(--deep)] flex items-center gap-1">
                <span>Final: {result.finalUrl}</span>
                <span className="text-[10px] text-[var(--muted)]">({result.httpInfo.redirectChain.length - 1} redirect)</span>
              </p>
            )}
          </div>
        </div>

        {/* Export & Rescan Controls (ISSUE-049) */}
        <ExportControls result={result} isScanning={isScanning} onRescan={onRescan} />
      </div>

      {/* Partial scan notice if applicable (ISSUE-028) */}
      {result.completeness === "partial" && (
        <div className="mt-4 p-3.5 rounded-xl bg-[var(--warning-bg)] border border-[var(--warning)]/30 text-xs text-[var(--dark)] flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-[var(--warning)] shrink-0 mt-0.5" />
          <div>
            <span className="font-bold">Partial Audit Notice:</span> One or more inspection limits were reached (e.g. payload size exceeded limit). Findings represent all fully inspected portions of the document.
          </div>
        </div>
      )}

      {/* 2. Metrics & Severity Breakdown Grid (ISSUE-045) */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 my-6">
        <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
          <div className="text-2xl sm:text-3xl font-black text-[var(--dark)]">
            {result.summary.totalFindings}
          </div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
            Total Issues
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
          <div className="text-2xl sm:text-3xl font-black text-[var(--error)]">
            {result.summary.highCount}
          </div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
            High Severity
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
          <div className="text-2xl sm:text-3xl font-black text-[var(--warning)]">
            {result.summary.mediumCount}
          </div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
            Medium Severity
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
          <div className="text-2xl sm:text-3xl font-black text-[var(--success)]">
            {result.summary.passedCount}
          </div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
            Passing Checks
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)] col-span-2 sm:col-span-1">
          <div className="text-2xl sm:text-3xl font-black text-[var(--dark)] font-mono">
            {result.httpInfo.responseTimeMs}<span className="text-sm font-normal">ms</span>
          </div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
            TTFB Latency
          </div>
        </div>
      </div>

      {/* 2.5 Audit Coverage & Scope Indicator (Phase 12) */}
      {result.coverage && (
        <div className="mb-6 p-4 rounded-2xl bg-white/40 border border-[var(--border)] text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2 pb-2 border-b border-[var(--border)]">
            <span className="font-extrabold uppercase tracking-wider text-[var(--muted)] text-[11px]">
              Audit Scope & Check Coverage
            </span>
            <span className="font-mono text-[var(--muted)] text-[11px]">
              {result.coverage.completedChecks} / {result.coverage.attemptedChecks} checks evaluated
            </span>
          </div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[var(--text-primary)]">
            <span>✅ <strong>{result.coverage.completedChecks}</strong> Completed</span>
            {result.coverage.unableToCheckCount > 0 && (
              <span className="text-[var(--warning)] font-semibold">
                ⚠️ <strong>{result.coverage.unableToCheckCount}</strong> Unable to Check
              </span>
            )}
            {result.coverage.failedChecksCount > 0 && (
              <span className="text-[var(--error)] font-semibold">
                ❌ <strong>{result.coverage.failedChecksCount}</strong> Failed
              </span>
            )}
          </div>
          {result.coverage.limitations.length > 0 && (
            <div className="mt-2.5 pt-2 border-t border-[var(--border)] text-[11px] text-[var(--muted)] space-y-0.5">
              {result.coverage.limitations.map((lim, i) => (
                <div key={i} className="flex items-start gap-1.5">
                  <span className="text-[var(--warning)]">ℹ️</span>
                  <span>{lim}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 3. Detected Technologies */}
      {result.technologies.length > 0 && (
        <div className="p-4 sm:p-5 rounded-2xl bg-white/40 border border-[var(--border)]">
          <div className="flex items-center gap-2 text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-3">
            <Cpu className="w-4 h-4 text-[var(--text-primary)]" />
            <span>Detected Technology Stack</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {result.technologies.map((tech) => (
              <div
                key={tech.name}
                className="px-3 py-1.5 rounded-xl border border-[var(--border)] bg-white/60 text-xs font-semibold text-[var(--text-primary)] flex items-center gap-2 shadow-2xs"
                title={tech.evidence ? `Evidence: ${tech.evidence}` : undefined}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--deep)]" />
                <span>{tech.name}</span>
                {tech.version && (
                  <span className="font-mono text-[10px] text-[var(--muted)]">v{tech.version}</span>
                )}
                <span className="text-[10px] font-bold text-[var(--muted)] bg-black/5 px-1.5 py-0.5 rounded">
                  {tech.category}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
