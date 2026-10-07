"use client";

import React, { useState } from "react";
import { Server, CheckCircle2, ChevronDown, ChevronUp, Check } from "lucide-react";
import { Finding, HttpInspectionInfo, PassedCheck } from "@/types/audit";
import { FindingItem } from "./FindingItem";

interface FindingListProps {
  findings: Finding[];
  passedChecks: PassedCheck[];
  httpInfo: HttpInspectionInfo;
  expandedFindings: Record<string, boolean>;
  onToggleExpand: (id: string) => void;
}

/**
 * Findings list container rendering individual ordered finding cards,
 * verified passing checks, and HTTP infrastructure headers explorer.
 */
export function FindingList({
  findings,
  passedChecks,
  httpInfo,
  expandedFindings,
  onToggleExpand,
}: FindingListProps) {
  const [showHeaders, setShowHeaders] = useState(false);
  const [showPassed, setShowPassed] = useState(false);

  return (
    <div className="space-y-6">
      {/* Findings Cards */}
      <div className="space-y-3" role="feed" aria-label="Audit findings list">
        {findings.length === 0 ? (
          <div className="p-8 text-center rounded-2xl border border-[var(--border)] bg-white/30 text-[var(--muted)] text-sm">
            Zero findings matching current search & filter criteria.
          </div>
        ) : (
          findings.map((finding) => (
            <FindingItem
              key={finding.id}
              finding={finding}
              isExpanded={!!expandedFindings[finding.id]}
              onToggleExpand={() => onToggleExpand(finding.id)}
            />
          ))
        )}
      </div>

      {/* HTTP Inspection & Headers Explorer */}
      <div className="pt-6 border-t border-[var(--border)]">
        <div
          className="flex items-center justify-between cursor-pointer select-none"
          onClick={() => setShowHeaders(!showHeaders)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              setShowHeaders(!showHeaders);
            }
          }}
          aria-expanded={showHeaders}
        >
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-[var(--muted)]">
            <Server className="w-4 h-4 text-[var(--dark)]" />
            <span>HTTP & Infrastructure Telemetry</span>
          </div>
          <button
            type="button"
            className="text-xs font-bold text-[var(--muted)] hover:text-[var(--text-primary)] flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-[var(--deep)] rounded"
          >
            <span>{showHeaders ? "Hide Headers" : "Inspect Raw Headers"}</span>
            {showHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>

        {showHeaders && (
          <div className="mt-4 p-5 rounded-2xl bg-[var(--dark)] text-[var(--white)] font-mono text-xs overflow-x-auto space-y-1.5 animate-in fade-in">
            <div className="text-[var(--surface)] mb-2 font-sans font-bold">
              HTTP Status: {httpInfo.statusCode} {httpInfo.statusText} · Protocol: {httpInfo.protocol}
            </div>
            {Object.entries(httpInfo.headers).map(([key, val]) => (
              <div key={key}>
                <span className="text-[var(--surface)] font-semibold">{key}:</span> {val}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Passing Checks Accordion */}
      <div className="pt-4 border-t border-[var(--border)]">
        <div
          className="flex items-center justify-between cursor-pointer select-none"
          onClick={() => setShowPassed(!showPassed)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              setShowPassed(!showPassed);
            }
          }}
          aria-expanded={showPassed}
        >
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-[var(--success)]">
            <CheckCircle2 className="w-4 h-4" />
            <span>Verified Passing Baseline Checks ({passedChecks.length})</span>
          </div>
          <button
            type="button"
            className="text-xs font-bold text-[var(--muted)] hover:text-[var(--text-primary)] flex items-center gap-1 focus-visible:ring-2 focus-visible:ring-[var(--deep)] rounded"
          >
            <span>{showPassed ? "Collapse" : "View Passing Checks"}</span>
            {showPassed ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>

        {showPassed && (
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2.5 animate-in fade-in">
            {passedChecks.map((check) => (
              <div
                key={check.id}
                className="p-3.5 rounded-xl bg-white/40 border border-[var(--border)] text-xs flex items-start gap-2.5"
              >
                <Check className="w-4 h-4 text-[var(--success)] shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold text-[var(--dark)] block">{check.title}</span>
                  <span className="text-[var(--muted)]">{check.detail}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
