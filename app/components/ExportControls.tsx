"use client";

import React, { useState } from "react";
import { Copy, Check, Download, RotateCw } from "lucide-react";
import { ScanResult } from "@/types/audit";
import { generateIssuesMarkdown } from "@/lib/exportMarkdown";
import { downloadJsonFile, downloadMarkdownFile } from "@/lib/exportJson";

interface ExportControlsProps {
  result: ScanResult;
  isScanning: boolean;
  onRescan: () => void;
}

/**
 * Grouped export and rescan controls conforming to ISSUE-049.
 * Replaces browser alert() with non-disruptive inline feedback conforming to ISSUE-035.
 */
export function ExportControls({ result, isScanning, onRescan }: ExportControlsProps) {
  const [copySuccess, setCopySuccess] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const handleCopyMarkdown = async () => {
    try {
      const md = generateIssuesMarkdown(result);
      await navigator.clipboard.writeText(md);
      setCopySuccess(true);
      showToast("Markdown report copied to clipboard.");
      setTimeout(() => setCopySuccess(false), 2000);
    } catch {
      showToast("Clipboard access denied. Please use the Download button instead.");
    }
  };

  const handleDownloadMarkdown = () => {
    const md = generateIssuesMarkdown(result);
    downloadMarkdownFile(md, result.hostname);
    showToast("Downloaded issues.md artifact.");
  };

  const handleDownloadJson = () => {
    downloadJsonFile(result);
    showToast("Downloaded JSON audit data.");
  };

  return (
    <div className="relative">
      <div className="flex flex-wrap items-center gap-2" role="toolbar" aria-label="Export and rescan actions">
        <button
          type="button"
          onClick={handleCopyMarkdown}
          className="px-3.5 py-2 rounded-xl border border-[var(--border)] bg-white/50 hover:bg-white/90 text-xs font-bold text-[var(--text-primary)] flex items-center gap-2 transition-all shadow-2xs focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
          title="Copy Markdown report formatted for AI prompts and issue trackers"
        >
          {copySuccess ? <Check className="w-3.5 h-3.5 text-[var(--success)]" /> : <Copy className="w-3.5 h-3.5 text-[var(--muted)]" />}
          <span>{copySuccess ? "Copied" : "Copy Markdown"}</span>
        </button>

        <button
          type="button"
          onClick={handleDownloadMarkdown}
          className="px-3.5 py-2 rounded-xl bg-[var(--deep)] text-[var(--white)] text-xs font-bold flex items-center gap-2 hover:opacity-90 transition-all shadow-xs focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
          title="Download issues.md artifact"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export issues.md</span>
        </button>

        <button
          type="button"
          onClick={handleDownloadJson}
          className="px-3 py-2 rounded-xl border border-[var(--border)] bg-white/50 hover:bg-white/90 text-xs font-bold text-[var(--text-primary)] transition-all focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
          title="Download raw structured JSON audit data"
        >
          JSON
        </button>

        <button
          type="button"
          onClick={onRescan}
          disabled={isScanning}
          className="px-3 py-2 rounded-xl border border-[var(--border)] bg-white/50 hover:bg-white/90 text-xs font-bold text-[var(--text-primary)] flex items-center gap-1.5 transition-all disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
          title="Re-run audit to verify resolved issues"
        >
          <RotateCw className={`w-3.5 h-3.5 ${isScanning ? "animate-spin" : ""}`} />
          <span>Rescan</span>
        </button>
      </div>

      {/* Accessible non-disruptive feedback message (ISSUE-035) */}
      {toastMessage && (
        <div
          role="status"
          aria-live="polite"
          className="absolute right-0 top-full mt-2 z-20 px-3 py-1.5 rounded-lg bg-[var(--dark)] text-[var(--white)] text-xs font-medium shadow-md animate-in fade-in slide-in-from-top-1"
        >
          {toastMessage}
        </div>
      )}
    </div>
  );
}
