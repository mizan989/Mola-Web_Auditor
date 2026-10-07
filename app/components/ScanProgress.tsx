"use client";

import React from "react";
import { RotateCw, ShieldCheck, Globe, Search, Layers } from "lucide-react";

interface ScanProgressProps {
  isScanning: boolean;
  scanMode: "quick" | "deep";
}

/**
 * Scan progress indicator conforming to ISSUE-026 (Zero fabricated percentages or timers).
 * Displays authentic active operational status and clean loading indicators.
 */
export function ScanProgress({ isScanning, scanMode }: ScanProgressProps) {
  if (!isScanning) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="w-full max-w-2xl mx-auto mt-6 p-6 rounded-2xl border border-[var(--border)] bg-white/40 backdrop-blur-md shadow-sm text-left animate-in fade-in duration-200"
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <RotateCw className="w-5 h-5 text-[var(--dark)] animate-spin" />
          <div>
            <h4 className="text-sm font-extrabold text-[var(--dark)]">
              Auditing Target Website ({scanMode === "deep" ? "Deep Scan" : "Quick Scan"})
            </h4>
            <p className="text-xs text-[var(--muted)] mt-0.5">
              Inspecting HTTP headers, TLS handshake, document structure, and subresources…
            </p>
          </div>
        </div>
      </div>

      {/* Indeterminate loading bar */}
      <div className="w-full h-1.5 bg-black/10 rounded-full overflow-hidden mb-4 relative">
        <div className="h-full bg-[var(--deep)] rounded-full w-1/3 animate-[pulse_1.5s_ease-in-out_infinite]" />
      </div>

      {/* Verified Operation Stages */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-semibold text-[var(--muted)]">
        <div className="p-2 rounded-xl bg-white/50 border border-[var(--border)] flex items-center gap-1.5">
          <Globe className="w-3.5 h-3.5 text-[var(--dark)]" />
          <span>SSRF / DNS</span>
        </div>
        <div className="p-2 rounded-xl bg-white/50 border border-[var(--border)] flex items-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-[var(--dark)]" />
          <span>HTTP & TLS</span>
        </div>
        <div className="p-2 rounded-xl bg-white/50 border border-[var(--border)] flex items-center gap-1.5">
          <Search className="w-3.5 h-3.5 text-[var(--dark)]" />
          <span>SEO & A11y</span>
        </div>
        <div className="p-2 rounded-xl bg-white/50 border border-[var(--border)] flex items-center gap-1.5">
          <Layers className="w-3.5 h-3.5 text-[var(--dark)]" />
          <span>{scanMode === "deep" ? "Deep Assets" : "Audit Checks"}</span>
        </div>
      </div>
    </div>
  );
}
