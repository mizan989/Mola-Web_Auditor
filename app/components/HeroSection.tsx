"use client";

import React from "react";
import { Search, ArrowRight, RotateCw } from "lucide-react";

interface HeroSectionProps {
  urlInput: string;
  setUrlInput: (val: string) => void;
  scanMode: "quick" | "deep";
  setScanMode: (mode: "quick" | "deep") => void;
  isScanning: boolean;
  onStartScan: () => void;
}

/**
 * Hero Section adhering to ISSUE-043 (removed 'Open-Source Evidence-Based Web Auditing' pill)
 * and ISSUE-044 (removed Quick Presets row).
 * Preserves full-screen height, typography, spacing, and glassmorphism.
 */
export function HeroSection({
  urlInput,
  setUrlInput,
  scanMode,
  setScanMode,
  isScanning,
  onStartScan,
}: HeroSectionProps) {
  return (
    <section className="min-h-[calc(100dvh-72px)] flex flex-col justify-center items-center px-4 sm:px-6 py-6 sm:py-10 text-center">
      <div className="w-full max-w-3xl mx-auto -translate-y-2 sm:-translate-y-6">
        <h1 className="text-4xl sm:text-6xl md:text-7xl font-extrabold tracking-tight text-[var(--text-primary)] leading-[1.05] mb-6">
          Audit your website.
          <br />
          <span className="text-[var(--muted)]">Fix what actually matters.</span>
        </h1>

        <p className="text-base sm:text-lg text-[var(--muted)] max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
          A focused developer audit engine. Enter any public website URL to receive concrete, reproducible evidence across Security headers, Performance, SEO, and Accessibility.
        </p>

        {/* Audit Target Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onStartScan();
          }}
          className="w-full max-w-2xl mx-auto"
        >
          <div className="p-2 sm:p-2.5 rounded-2xl border border-[var(--border)] bg-white/40 shadow-sm backdrop-blur-md flex flex-col sm:flex-row items-stretch gap-2.5">
            <div className="flex-1 relative flex items-center">
              <label htmlFor="target-url-input" className="sr-only">
                Target Website URL
              </label>
              <Search className="w-5 h-5 text-[var(--muted)] absolute left-3.5 pointer-events-none" />
              <input
                id="target-url-input"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com"
                className="w-full pl-11 pr-4 py-3 bg-transparent text-[var(--text-primary)] placeholder-[var(--muted)]/70 text-sm sm:text-base outline-none font-medium focus-visible:ring-2 focus-visible:ring-[var(--deep)] rounded-xl"
                disabled={isScanning}
                autoComplete="url"
              />
            </div>

            {/* Scan Mode Selector */}
            <div
              className="flex items-center gap-1 bg-white/50 p-1 rounded-xl border border-[var(--border)] self-center sm:self-auto"
              role="radiogroup"
              aria-label="Scan Mode"
            >
              <button
                type="button"
                role="radio"
                aria-checked={scanMode === "quick"}
                onClick={() => setScanMode("quick")}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all focus-visible:ring-2 focus-visible:ring-[var(--deep)] ${
                  scanMode === "quick"
                    ? "bg-[var(--deep)] text-[var(--white)] shadow-xs"
                    : "text-[var(--muted)] hover:text-[var(--text-primary)]"
                }`}
                title="Quick Scan: Fast headers, HTML DOM, SEO, accessibility, and tech detection"
              >
                Quick
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={scanMode === "deep"}
                onClick={() => setScanMode("deep")}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all focus-visible:ring-2 focus-visible:ring-[var(--deep)] ${
                  scanMode === "deep"
                    ? "bg-[var(--deep)] text-[var(--white)] shadow-xs"
                    : "text-[var(--muted)] hover:text-[var(--text-primary)]"
                }`}
                title="Deep Scan: Adds Subresource Integrity, cookie security, iframe audit, and deep resource inspection"
              >
                Deep
              </button>
            </div>

            <button
              type="submit"
              disabled={isScanning || !urlInput.trim()}
              className="px-7 py-3 rounded-xl bg-[var(--deep)] text-[var(--white)] font-bold text-sm hover:opacity-95 active:scale-[0.98] transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
            >
              {isScanning ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  <span>Auditing…</span>
                </>
              ) : (
                <>
                  <span>Audit</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>

        <p className="text-xs text-[var(--muted)] mt-6 font-medium">
          Ephemeral in-memory processing · SSRF protected · Zero database persistence
        </p>
      </div>
    </section>
  );
}
