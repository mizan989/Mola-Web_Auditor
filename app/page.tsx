"use client";

import React, { useState, useMemo, useEffect } from "react";
import { AlertTriangle, Shield, Cpu, Code2 } from "lucide-react";
import {
  Finding,
  FindingCategory,
  FindingSeverity,
  ScanResult,
  VerificationComparison,
} from "@/types/audit";
import { compareAuditResults } from "@/lib/compare";
import { HeroSection } from "./components/HeroSection";
import { ScanProgress } from "./components/ScanProgress";
import { VerificationSection } from "./components/VerificationSection";
import { ReportSummary } from "./components/ReportSummary";
import { FindingFilters } from "./components/FindingFilters";
import { FindingList } from "./components/FindingList";

const SESSION_STORAGE_KEY = "mola_session_audit";

export default function AuditorPage() {
  const [urlInput, setUrlInput] = useState("");
  const [scanMode, setScanMode] = useState<"quick" | "deep">("quick");
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Scan state (ISSUE-024: robust within active browser session)
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [verification, setVerification] = useState<VerificationComparison | null>(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<FindingSeverity | "all">("all");
  const [selectedCategory, setSelectedCategory] = useState<FindingCategory | "all">("all");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});

  // Restore previous scan from active tab session if present (ISSUE-024)
  useEffect(() => {
    try {
      const stored = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as ScanResult;
        setCurrentResult(parsed);
      }
    } catch {
      // Ignore session storage errors
    }
  }, []);

  // Trigger Scan
  const handleStartScan = async (targetToScan?: string) => {
    const rawTarget = targetToScan || urlInput.trim();
    if (!rawTarget) return;

    let normalized = rawTarget;
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = `https://${normalized}`;
    }

    setScanError(null);
    setIsScanning(true);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized, mode: scanMode }),
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(data.error || "Failed to scan website.");
      }

      // If we already had a scan for the same host, compute fix verification (ISSUE-024, ISSUE-025)
      if (currentResult && currentResult.hostname === data.hostname) {
        const comp = compareAuditResults(currentResult, data);
        setVerification(comp);
      } else {
        setVerification(null);
      }

      setCurrentResult(data);

      // Persist in active session memory
      try {
        sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data));
      } catch {
        // Ignore session storage quotas
      }

      // Auto expand high priority findings
      const initialExpanded: Record<string, boolean> = {};
      data.findings.forEach((f: Finding) => {
        if (f.severity === "high") {
          initialExpanded[f.id] = true;
        }
      });
      setExpandedFindings(initialExpanded);

      // Scroll to report smoothly
      setTimeout(() => {
        const reportEl = document.getElementById("report-results");
        if (reportEl) {
          reportEl.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }, 200);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Audit failed.";
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleClearFilters = () => {
    setSearchQuery("");
    setSelectedSeverity("all");
    setSelectedCategory("all");
  };

  // Filtered Findings
  const filteredFindings = useMemo(() => {
    if (!currentResult) return [];
    return currentResult.findings.filter((finding) => {
      if (selectedSeverity !== "all" && finding.severity !== selectedSeverity) {
        return false;
      }
      if (selectedCategory !== "all" && finding.category !== selectedCategory) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const inTitle = finding.title.toLowerCase().includes(q);
        const inDesc = finding.description.toLowerCase().includes(q);
        const inEvidence = finding.evidence.toLowerCase().includes(q);
        const inRec = finding.recommendation.toLowerCase().includes(q);
        const inTarget = (finding.affectedTarget || "").toLowerCase().includes(q);
        return inTitle || inDesc || inEvidence || inRec || inTarget;
      }
      return true;
    });
  }, [currentResult, selectedSeverity, selectedCategory, searchQuery]);

  return (
    <main className="w-full">
      {/* 1. Hero Section (ISSUE-043 removed pill, ISSUE-044 removed presets) */}
      <HeroSection
        urlInput={urlInput}
        setUrlInput={setUrlInput}
        scanMode={scanMode}
        setScanMode={setScanMode}
        isScanning={isScanning}
        onStartScan={() => handleStartScan()}
      />

      {/* 2. Authentic Scan Progress (ISSUE-026 zero fake progress) */}
      <ScanProgress isScanning={isScanning} scanMode={scanMode} />

      {/* 3. Error Banner */}
      {scanError && (
        <div
          role="alert"
          className="w-full max-w-2xl mx-auto mt-6 p-4 rounded-xl border border-[var(--error)]/30 bg-[var(--error-bg)] text-left flex items-start gap-3 text-sm text-[var(--error)] animate-in fade-in"
        >
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <div>
            <p className="font-bold">Audit Request Could Not Be Completed</p>
            <p className="text-xs mt-1 text-[var(--text-primary)]">{scanError}</p>
          </div>
        </div>
      )}

      {/* 4. Audit Report Section */}
      {currentResult && (
        <section id="report-results" className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-12 scroll-mt-24">
          {/* Fix Verification Diff (ISSUE-025, ISSUE-050) */}
          {verification && <VerificationSection comparison={verification} />}

          {/* Report Summary, Telemetry & Export Controls (ISSUE-045, ISSUE-049) */}
          <ReportSummary
            result={currentResult}
            isScanning={isScanning}
            onRescan={() => handleStartScan(currentResult.targetUrl)}
          />

          {/* Finding Search & Filters (ISSUE-048) */}
          <FindingFilters
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
            selectedSeverity={selectedSeverity}
            setSelectedSeverity={setSelectedSeverity}
            selectedCategory={selectedCategory}
            setSelectedCategory={setSelectedCategory}
            totalResults={filteredFindings.length}
            onClearFilters={handleClearFilters}
          />

          {/* Finding List & Detail Cards (ISSUE-046, ISSUE-047) */}
          <FindingList
            findings={filteredFindings}
            passedChecks={currentResult.passedChecks}
            httpInfo={currentResult.httpInfo}
            expandedFindings={expandedFindings}
            onToggleExpand={toggleExpand}
          />
        </section>
      )}

      {/* 5. Developer Workflow Section (Preserved Protected Section) */}
      <section
        id="workflow"
        className="w-full min-h-[calc(100dvh-72px)] flex flex-col justify-center items-center px-4 sm:px-6 py-6 sm:py-10 border-t border-[var(--border)] scroll-mt-[72px]"
      >
        <div className="w-full max-w-5xl mx-auto">
          <div className="mb-6 sm:mb-10 text-center sm:text-left">
            <p className="text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-1 sm:mb-2">
              Developer Workflow
            </p>
            <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-[var(--dark)]">
              From Detection to Verification
            </h2>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-4">
            <div className="p-3.5 sm:p-5 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm flex flex-col justify-between">
              <div>
                <span className="font-mono text-lg sm:text-2xl font-black text-[var(--muted)]/50 block mb-1.5 sm:mb-3">
                  01
                </span>
                <h3 className="text-xs sm:text-base font-bold text-[var(--dark)] mb-1 sm:mb-1.5">
                  Safe Discovery
                </h3>
                <p className="text-[10px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  Target URLs undergo strict SSRF validation before running controlled HTTP and DOM inspection passes.
                </p>
              </div>
            </div>

            <div className="p-3.5 sm:p-5 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm flex flex-col justify-between">
              <div>
                <span className="font-mono text-lg sm:text-2xl font-black text-[var(--muted)]/50 block mb-1.5 sm:mb-3">
                  02
                </span>
                <h3 className="text-xs sm:text-base font-bold text-[var(--dark)] mb-1 sm:mb-1.5">
                  Evidence-First
                </h3>
                <p className="text-[10px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  Every finding includes reproducible observations, exact header values, affected tags, and why it matters.
                </p>
              </div>
            </div>

            <div className="p-3.5 sm:p-5 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm flex flex-col justify-between">
              <div>
                <span className="font-mono text-lg sm:text-2xl font-black text-[var(--muted)]/50 block mb-1.5 sm:mb-3">
                  03
                </span>
                <h3 className="text-xs sm:text-base font-bold text-[var(--dark)] mb-1 sm:mb-1.5">
                  AI-Ready Export
                </h3>
                <p className="text-[10px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  Export an actionable <code className="text-[9px] sm:text-[11px] font-bold">issues.md</code> artifact directly feedable to Gemini, Claude, or GitHub Issues.
                </p>
              </div>
            </div>

            <div className="p-3.5 sm:p-5 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm flex flex-col justify-between">
              <div>
                <span className="font-mono text-lg sm:text-2xl font-black text-[var(--muted)]/50 block mb-1.5 sm:mb-3">
                  04
                </span>
                <h3 className="text-xs sm:text-base font-bold text-[var(--dark)] mb-1 sm:mb-1.5">
                  Fix Verification
                </h3>
                <p className="text-[10px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  Deploy your fix and hit Rescan. Mola automatically highlights resolved vs remaining issues.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 6. Capabilities Section (Preserved Protected Section) */}
      <section
        id="features"
        className="w-full min-h-[calc(100dvh-72px)] flex flex-col justify-center items-center px-4 sm:px-6 py-6 sm:py-10 border-t border-[var(--border)] scroll-mt-[72px]"
      >
        <div className="w-full max-w-5xl mx-auto">
          <div className="mb-6 sm:mb-10 text-center sm:text-left">
            <p className="text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-1 sm:mb-2">
              Capabilities
            </p>
            <h2 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-[var(--dark)]">
              Built for Developers Who Hate Fluff
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 sm:gap-4">
            <div className="p-4 sm:p-6 rounded-2xl border border-[var(--border)] bg-white/30 flex flex-col justify-between">
              <div>
                <Shield className="w-5 sm:w-6 h-5 sm:h-6 text-[var(--dark)] mb-2 sm:mb-3" />
                <h3 className="font-bold text-sm sm:text-base text-[var(--dark)] mb-1 sm:mb-2">
                  Zero Vanity Scores
                </h3>
                <p className="text-[11px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  No arbitrary 0–100 badges that provide false security. Clear, evidence-backed priorities sorted by impact.
                </p>
              </div>
            </div>

            <div className="p-4 sm:p-6 rounded-2xl border border-[var(--border)] bg-white/30 flex flex-col justify-between">
              <div>
                <Cpu className="w-5 sm:w-6 h-5 sm:h-6 text-[var(--dark)] mb-2 sm:mb-3" />
                <h3 className="font-bold text-sm sm:text-base text-[var(--dark)] mb-1 sm:mb-2">
                  Technology Fingerprinting
                </h3>
                <p className="text-[11px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  Instantly detects frameworks (Next.js, React, Nuxt), CDN edge hosts (Cloudflare, Vercel), and CMS software.
                </p>
              </div>
            </div>

            <div className="p-4 sm:p-6 rounded-2xl border border-[var(--border)] bg-white/30 flex flex-col justify-between">
              <div>
                <Code2 className="w-5 sm:w-6 h-5 sm:h-6 text-[var(--dark)] mb-2 sm:mb-3" />
                <h3 className="font-bold text-sm sm:text-base text-[var(--dark)] mb-1 sm:mb-2">
                  Ready-To-Use Code Fixes
                </h3>
                <p className="text-[11px] sm:text-xs text-[var(--muted)] leading-relaxed">
                  Each recommendation includes sample Nginx configs, CSP directives, and HTML snippets ready to copy into your repository.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
