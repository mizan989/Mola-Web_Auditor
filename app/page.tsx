"use client";

import React, { useState, useMemo } from "react";
import {
  Search,
  Shield,
  Zap,
  Globe,
  Eye,
  CheckCircle2,
  Copy,
  Check,
  Download,
  RotateCw,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Info,
  Server,
  Code2,
  Cpu,
  Layers,
  ArrowRight,
  Sparkles,
} from "lucide-react";
import {
  Finding,
  FindingCategory,
  FindingSeverity,
  ScanResult,
  VerificationComparison,
} from "@/types/audit";
import { generateIssuesMarkdown, generateVerificationMarkdown } from "@/lib/exportMarkdown";
import { downloadJsonFile, downloadMarkdownFile } from "@/lib/exportJson";
import { compareAuditResults } from "@/lib/compare";

const PRESET_URLS = [
  "https://example.com",
  "https://github.com",
  "https://nextjs.org",
];

const SCAN_STAGES = [
  "Resolving DNS & SSRF Validation",
  "Inspecting HTTP Headers & TLS",
  "Analyzing DOM, SEO & Accessibility",
  "Normalizing Evidence & Building Report",
];

export default function AuditorPage() {
  const [urlInput, setUrlInput] = useState("");
  const [scanMode, setScanMode] = useState<"quick" | "deep">("quick");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState(0);
  const [scanError, setScanError] = useState<string | null>(null);

  // Scan state
  const [previousResult, setPreviousResult] = useState<ScanResult | null>(null);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [verification, setVerification] = useState<VerificationComparison | null>(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<FindingSeverity | "all">("all");
  const [selectedCategory, setSelectedCategory] = useState<FindingCategory | "all">("all");
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [showHeaders, setShowHeaders] = useState(false);
  const [showPassed, setShowPassed] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);

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
    setScanProgress(10);
    setCurrentStage(0);

    // Visual progress animation
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 92) return prev;
        const next = prev + Math.floor(Math.random() * 8) + 4;
        const stageIdx = Math.min(Math.floor((next / 100) * SCAN_STAGES.length), SCAN_STAGES.length - 1);
        setCurrentStage(stageIdx);
        return next;
      });
    }, 180);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized, mode: scanMode }),
      });

      const data = await response.json();

      clearInterval(progressInterval);
      setScanProgress(100);

      if (!response.ok || data.error) {
        throw new Error(data.error || "Failed to scan website.");
      }

      // If we already had a scan for the same host, compute fix verification
      if (currentResult && currentResult.hostname === data.hostname) {
        const comp = compareAuditResults(currentResult, data);
        setVerification(comp);
        setPreviousResult(currentResult);
      } else {
        setVerification(null);
        setPreviousResult(null);
      }

      setCurrentResult(data);

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
      }, 250);
    } catch (err: unknown) {
      clearInterval(progressInterval);
      const msg = err instanceof Error ? err.message : "Audit failed.";
      setScanError(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedFindings((prev) => ({ ...prev, [id]: !prev[id] }));
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
        return inTitle || inDesc || inEvidence || inRec;
      }
      return true;
    });
  }, [currentResult, selectedSeverity, selectedCategory, searchQuery]);

  // Copy Markdown
  const handleCopyMarkdown = async () => {
    if (!currentResult) return;
    const md = generateIssuesMarkdown(currentResult);
    try {
      await navigator.clipboard.writeText(md);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch {
      alert("Clipboard copy unavailable in browser.");
    }
  };

  // Download issues.md
  const handleDownloadMarkdown = () => {
    if (!currentResult) return;
    const md = generateIssuesMarkdown(currentResult);
    downloadMarkdownFile(md, currentResult.hostname);
  };

  // Download JSON
  const handleDownloadJson = () => {
    if (!currentResult) return;
    downloadJsonFile(currentResult);
  };

  return (
    <main className="w-full">
      {/* Hero Section */}
      <section className="min-h-[calc(100vh-72px)] flex flex-col justify-center items-center px-6 py-16 sm:py-24 text-center">
        <div className="w-full max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[var(--border)] bg-white/40 text-[11px] font-extrabold uppercase tracking-widest text-[var(--muted)] mb-6 shadow-xs">
            <Sparkles className="w-3.5 h-3.5 text-[var(--text-primary)]" />
            <span>Open-Source Evidence-Based Web Auditing</span>
          </div>

          <h1 className="text-4xl sm:text-6xl md:text-7xl font-extrabold tracking-tight text-[var(--text-primary)] leading-[1.05] mb-6">
            Audit your website.<br />
            <span className="text-[var(--muted)]">Fix what actually matters.</span>
          </h1>

          <p className="text-base sm:text-lg text-[var(--muted)] max-w-2xl mx-auto mb-10 leading-relaxed font-normal">
            A focused developer audit engine. Enter any URL to receive concrete, reproducible evidence across Security headers, Performance, SEO, and Accessibility.
          </p>

          {/* Form */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleStartScan();
            }}
            className="w-full max-w-2xl mx-auto"
          >
            <div className="p-2 sm:p-2.5 rounded-2xl border border-[var(--border)] bg-white/40 shadow-sm backdrop-blur-md flex flex-col sm:flex-row items-stretch gap-2.5">
              <div className="flex-1 relative flex items-center">
                <Search className="w-5 h-5 text-[var(--muted)] absolute left-3.5 pointer-events-none" />
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full pl-11 pr-4 py-3 bg-transparent text-[var(--text-primary)] placeholder-[var(--muted)]/70 text-sm sm:text-base outline-none font-medium"
                  disabled={isScanning}
                />
              </div>

              {/* Mode selector */}
              <div className="flex items-center gap-1 bg-white/50 p-1 rounded-xl border border-[var(--border)] self-center sm:self-auto">
                <button
                  type="button"
                  onClick={() => setScanMode("quick")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                    scanMode === "quick"
                      ? "bg-[var(--deep)] text-[var(--white)] shadow-xs"
                      : "text-[var(--muted)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  Quick
                </button>
                <button
                  type="button"
                  onClick={() => setScanMode("deep")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                    scanMode === "deep"
                      ? "bg-[var(--deep)] text-[var(--white)] shadow-xs"
                      : "text-[var(--muted)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  Deep
                </button>
              </div>

              <button
                type="submit"
                disabled={isScanning || !urlInput.trim()}
                className="px-7 py-3 rounded-xl bg-[var(--deep)] text-[var(--white)] font-bold text-sm hover:opacity-95 active:scale-[0.98] transition-all shadow-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
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

          {/* Preset Buttons */}
          <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs text-[var(--muted)]">
            <span className="font-semibold mr-1">Quick presets:</span>
            {PRESET_URLS.map((url) => (
              <button
                key={url}
                type="button"
                onClick={() => {
                  setUrlInput(url);
                  handleStartScan(url);
                }}
                className="px-2.5 py-1 rounded-md border border-[var(--border)] bg-white/30 hover:bg-white/70 text-[var(--text-primary)] font-mono text-[11px] transition-all"
              >
                {url.replace("https://", "")}
              </button>
            ))}
          </div>

          {/* Progress / Status Panel */}
          {isScanning && (
            <div className="mt-8 p-5 rounded-2xl border border-[var(--border)] bg-white/40 backdrop-blur-md text-left shadow-sm animate-in fade-in duration-200">
              <div className="flex items-center justify-between text-xs font-bold mb-2">
                <span className="text-[var(--dark)] flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[var(--warning)] animate-ping" />
                  {SCAN_STAGES[currentStage]}
                </span>
                <span className="text-[var(--muted)] font-mono">{scanProgress}%</span>
              </div>

              <div className="w-full h-1.5 bg-black/10 rounded-full overflow-hidden mb-3">
                <div
                  className="h-full bg-[var(--deep)] transition-all duration-300 rounded-full"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-semibold text-[var(--muted)]">
                {SCAN_STAGES.map((stage, idx) => (
                  <div
                    key={stage}
                    className={`p-1.5 rounded-md border ${
                      idx <= currentStage
                        ? "border-[var(--dark)]/30 text-[var(--dark)] bg-white/40"
                        : "border-transparent opacity-50"
                    }`}
                  >
                    {idx + 1}. {stage.split(" ")[0]}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Error Message */}
          {scanError && (
            <div className="mt-6 p-4 rounded-xl border border-[var(--error)]/30 bg-[var(--error-bg)] text-left flex items-start gap-3 text-sm text-[var(--error)]">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-bold">Scan Could Not Be Completed</p>
                <p className="text-xs mt-1 text-[var(--text-primary)]">{scanError}</p>
              </div>
            </div>
          )}

          <p className="text-xs text-[var(--muted)] mt-6 font-medium">
            100% Free · Open Source · SSRF Protected · No Account Required
          </p>
        </div>
      </section>

      {/* Audit Report Section */}
      {currentResult && (
        <section id="report-results" className="w-full max-w-5xl mx-auto px-6 py-12 scroll-mt-24">
          {/* Fix Verification Callout if available */}
          {verification && (
            <div className="mb-8 p-6 rounded-2xl border-2 border-[var(--success)] bg-[var(--success-bg)] backdrop-blur-sm animate-in fade-in">
              <div className="flex items-center gap-3 font-extrabold text-base text-[var(--success)] mb-2">
                <CheckCircle2 className="w-5 h-5" />
                <span>Fix Verification Completed for {verification.targetUrl}</span>
              </div>
              <p className="text-xs text-[var(--text-primary)] mb-4">
                Compared against previous scan ({new Date(verification.previousScanTimestamp).toLocaleTimeString()}).
              </p>

              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-3 rounded-xl bg-white/60 border border-[var(--border)]">
                  <div className="text-2xl font-black text-[var(--success)]">
                    {verification.resolvedFindings.length}
                  </div>
                  <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)]">Resolved</div>
                </div>
                <div className="p-3 rounded-xl bg-white/60 border border-[var(--border)]">
                  <div className="text-2xl font-black text-[var(--warning)]">
                    {verification.remainingFindings.length}
                  </div>
                  <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)]">Remaining</div>
                </div>
                <div className="p-3 rounded-xl bg-white/60 border border-[var(--border)]">
                  <div className="text-2xl font-black text-[var(--error)]">
                    {verification.newFindings.length}
                  </div>
                  <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)]">New Issues</div>
                </div>
              </div>
            </div>
          )}

          {/* Main Report Card */}
          <div className="p-6 sm:p-8 rounded-3xl border border-[var(--border)] bg-white/35 backdrop-blur-md shadow-sm">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[var(--border)] gap-4">
              <div>
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-[var(--muted)] mb-1">
                  <span>Audit Report</span>
                  <span>·</span>
                  <span className="font-mono text-[var(--dark)]">{currentResult.scanMode.toUpperCase()} SCAN</span>
                </div>
                <h2 className="text-2xl sm:text-3xl font-black tracking-tight text-[var(--dark)]">
                  {currentResult.hostname}
                </h2>
                <p className="text-xs text-[var(--muted)] mt-1 font-mono">
                  {currentResult.targetUrl} · {new Date(currentResult.scanTimestamp).toLocaleTimeString()}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyMarkdown}
                  className="px-3.5 py-2 rounded-xl border border-[var(--border)] bg-white/50 hover:bg-white/90 text-xs font-bold text-[var(--text-primary)] flex items-center gap-2 transition-all shadow-2xs"
                >
                  {copySuccess ? <Check className="w-3.5 h-3.5 text-[var(--success)]" /> : <Copy className="w-3.5 h-3.5 text-[var(--muted)]" />}
                  <span>{copySuccess ? "Copied" : "Copy Markdown"}</span>
                </button>

                <button
                  type="button"
                  onClick={handleDownloadMarkdown}
                  className="px-3.5 py-2 rounded-xl bg-[var(--deep)] text-[var(--white)] text-xs font-bold flex items-center gap-2 hover:opacity-90 transition-all shadow-xs"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export issues.md</span>
                </button>

                <button
                  type="button"
                  onClick={handleDownloadJson}
                  className="px-3 py-2 rounded-xl border border-[var(--border)] bg-white/50 hover:bg-white/90 text-xs font-bold text-[var(--text-primary)] transition-all"
                  title="Export raw JSON"
                >
                  JSON
                </button>

                <button
                  type="button"
                  onClick={() => handleStartScan(currentResult.targetUrl)}
                  disabled={isScanning}
                  className="px-3 py-2 rounded-xl border border-[var(--border)] bg-white/50 hover:bg-white/90 text-xs font-bold text-[var(--text-primary)] flex items-center gap-1.5 transition-all"
                >
                  <RotateCw className={`w-3.5 h-3.5 ${isScanning ? "animate-spin" : ""}`} />
                  <span>Rescan</span>
                </button>
              </div>
            </div>

            {/* Metrics Overview Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 my-6">
              <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
                <div className="text-2xl sm:text-3xl font-black text-[var(--dark)]">
                  {currentResult.summary.totalFindings}
                </div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
                  Findings
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
                <div className="text-2xl sm:text-3xl font-black text-[var(--error)]">
                  {currentResult.summary.highCount}
                </div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
                  High Priority
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
                <div className="text-2xl sm:text-3xl font-black text-[var(--warning)]">
                  {currentResult.summary.mediumCount}
                </div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
                  Medium
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)]">
                <div className="text-2xl sm:text-3xl font-black text-[var(--success)]">
                  {currentResult.summary.passedCount}
                </div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
                  Checks Passed
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-white/50 border border-[var(--border)] col-span-2 sm:col-span-1">
                <div className="text-2xl sm:text-3xl font-black text-[var(--dark)] font-mono">
                  {currentResult.httpInfo.responseTimeMs}<span className="text-sm font-normal">ms</span>
                </div>
                <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--muted)] mt-1">
                  TTFB Latency
                </div>
              </div>
            </div>

            {/* Detected Technologies Bento */}
            {currentResult.technologies.length > 0 && (
              <div className="p-5 rounded-2xl bg-white/40 border border-[var(--border)] mb-6">
                <div className="flex items-center gap-2 text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-3">
                  <Cpu className="w-4 h-4 text-[var(--text-primary)]" />
                  <span>Detected Technology Stack</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {currentResult.technologies.map((tech) => (
                    <div
                      key={tech.name}
                      className="px-3 py-1.5 rounded-xl border border-[var(--border)] bg-white/60 text-xs font-semibold text-[var(--text-primary)] flex items-center gap-2 shadow-2xs"
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

            {/* Filter and Search Bar */}
            <div className="p-4 rounded-2xl bg-white/40 border border-[var(--border)] mb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex-1 relative">
                <Search className="w-4 h-4 text-[var(--muted)] absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter findings by title, evidence, or tag…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-white/60 rounded-xl border border-[var(--border)] text-xs text-[var(--text-primary)] placeholder-[var(--muted)] outline-none"
                />
              </div>

              {/* Severity Pills */}
              <div className="flex flex-wrap items-center gap-1 text-xs">
                {(["all", "high", "medium", "low"] as const).map((sev) => (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => setSelectedSeverity(sev)}
                    className={`px-3 py-1.5 rounded-lg font-bold capitalize transition-all ${
                      selectedSeverity === sev
                        ? "bg-[var(--deep)] text-[var(--white)] shadow-2xs"
                        : "text-[var(--muted)] hover:text-[var(--text-primary)] bg-white/40"
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              {/* Category Pills */}
              <div className="flex flex-wrap items-center gap-1 text-xs">
                {(["all", "security", "performance", "seo", "accessibility"] as const).map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setSelectedCategory(cat)}
                    className={`px-2.5 py-1.5 rounded-lg font-semibold capitalize transition-all ${
                      selectedCategory === cat
                        ? "bg-[var(--dark)] text-[var(--white)] shadow-2xs"
                        : "text-[var(--muted)] hover:text-[var(--text-primary)] bg-white/40"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Findings List */}
            <div className="space-y-3">
              {filteredFindings.length === 0 ? (
                <div className="p-8 text-center rounded-2xl border border-[var(--border)] bg-white/30 text-[var(--muted)] text-sm">
                  No findings matching current search & filter criteria.
                </div>
              ) : (
                filteredFindings.map((finding) => {
                  const isExpanded = !!expandedFindings[finding.id];
                  const severityBorder =
                    finding.severity === "high"
                      ? "border-l-[var(--error)]"
                      : finding.severity === "medium"
                      ? "border-l-[var(--warning)]"
                      : "border-l-[var(--success)]";

                  return (
                    <article
                      key={finding.id}
                      className={`p-5 rounded-2xl border border-[var(--border)] border-l-4 ${severityBorder} bg-white/45 backdrop-blur-xs transition-all shadow-xs`}
                    >
                      <div
                        className="flex items-start justify-between gap-4 cursor-pointer select-none"
                        onClick={() => toggleExpand(finding.id)}
                      >
                        <div className="flex-1">
                          <div className="flex items-center gap-2 text-[10px] font-extrabold uppercase tracking-wider text-[var(--muted)] mb-1">
                            <span
                              className={`px-2 py-0.5 rounded font-black ${
                                finding.severity === "high"
                                  ? "bg-[var(--error-bg)] text-[var(--error)]"
                                  : finding.severity === "medium"
                                  ? "bg-[var(--warning-bg)] text-[var(--warning)]"
                                  : "bg-[var(--success-bg)] text-[var(--success)]"
                              }`}
                            >
                              {finding.severity}
                            </span>
                            <span>·</span>
                            <span>{finding.category}</span>
                            <span>·</span>
                            <span className="text-[var(--muted)]">{finding.priority.replace("-", " ")}</span>
                          </div>

                          <h3 className="text-base sm:text-lg font-bold text-[var(--dark)]">
                            {finding.title}
                          </h3>
                          <p className="text-xs sm:text-sm text-[var(--muted)] mt-1">
                            {finding.description}
                          </p>
                        </div>

                        <button
                          type="button"
                          className="p-1.5 rounded-lg hover:bg-white/60 text-[var(--muted)]"
                          aria-label={isExpanded ? "Collapse finding details" : "Expand finding details"}
                        >
                          {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                        </button>
                      </div>

                      {/* Expandable Details */}
                      {isExpanded && (
                        <div className="mt-4 pt-4 border-t border-[var(--border)] space-y-3.5 text-xs text-[var(--text-primary)]">
                          {/* Why It Matters */}
                          <div>
                            <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
                              Why it matters
                            </span>
                            <p className="text-[var(--text-primary)] leading-relaxed">
                              {finding.whyItMatters}
                            </p>
                          </div>

                          {/* Evidence */}
                          <div>
                            <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
                              Concrete Evidence
                            </span>
                            <pre className="p-3 rounded-xl bg-[var(--dark)] text-[var(--white)] font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                              {finding.evidence}
                            </pre>
                          </div>

                          {/* Affected target */}
                          {finding.affectedTarget && (
                            <div>
                              <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-0.5">
                                Affected Resource
                              </span>
                              <code className="px-2 py-1 rounded bg-white/60 border border-[var(--border)] font-mono text-[11px] text-[var(--dark)]">
                                {finding.affectedTarget}
                              </code>
                            </div>
                          )}

                          {/* Recommendation & Code snippet */}
                          <div>
                            <span className="font-extrabold uppercase tracking-wider text-[10px] text-[var(--muted)] block mb-1">
                              Recommended Fix
                            </span>
                            <p className="text-[var(--dark)] font-medium mb-2">
                              {finding.recommendation}
                            </p>
                            {finding.codeSnippet && (
                              <pre className="p-3 rounded-xl bg-[var(--deep)] text-[var(--white)] font-mono text-xs overflow-x-auto">
                                <code>{finding.codeSnippet}</code>
                              </pre>
                            )}
                          </div>
                        </div>
                      )}
                    </article>
                  );
                })
              )}
            </div>

            {/* HTTP Inspection & Headers Explorer */}
            <div className="mt-8 pt-6 border-t border-[var(--border)]">
              <div
                className="flex items-center justify-between cursor-pointer select-none"
                onClick={() => setShowHeaders(!showHeaders)}
              >
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-[var(--muted)]">
                  <Server className="w-4 h-4 text-[var(--dark)]" />
                  <span>HTTP & Infrastructure Telemetry</span>
                </div>
                <button type="button" className="text-xs font-bold text-[var(--muted)] hover:text-[var(--text-primary)] flex items-center gap-1">
                  <span>{showHeaders ? "Hide Headers" : "Inspect Raw Headers"}</span>
                  {showHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {showHeaders && (
                <div className="mt-4 p-4 rounded-2xl bg-[var(--dark)] text-[var(--white)] font-mono text-xs overflow-x-auto space-y-1">
                  <div className="text-[var(--surface)] mb-2 font-sans font-bold">
                    HTTP Status: {currentResult.httpInfo.statusCode} {currentResult.httpInfo.statusText} · Protocol: {currentResult.httpInfo.protocol}
                  </div>
                  {Object.entries(currentResult.httpInfo.headers).map(([key, val]) => (
                    <div key={key}>
                      <span className="text-[var(--surface)]">{key}:</span> {val}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Passed Checks Accordion */}
            <div className="mt-6 pt-4 border-t border-[var(--border)]">
              <div
                className="flex items-center justify-between cursor-pointer select-none"
                onClick={() => setShowPassed(!showPassed)}
              >
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-[var(--success)]">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Verified Passing Baseline Checks ({currentResult.passedChecks.length})</span>
                </div>
                <button type="button" className="text-xs font-bold text-[var(--muted)] hover:text-[var(--text-primary)] flex items-center gap-1">
                  <span>{showPassed ? "Collapse" : "View Passing Checks"}</span>
                  {showPassed ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {showPassed && (
                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {currentResult.passedChecks.map((check) => (
                    <div
                      key={check.id}
                      className="p-3 rounded-xl bg-white/40 border border-[var(--border)] text-xs flex items-start gap-2.5"
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
        </section>
      )}

      {/* Workflow Section */}
      <section id="workflow" className="w-full max-w-5xl mx-auto px-6 py-20 border-t border-[var(--border)]">
        <div className="mb-12">
          <p className="text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-2">Developer Workflow</p>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[var(--dark)]">
            From Detection to Verification
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
            <span className="font-mono text-2xl font-black text-[var(--muted)]/50 block mb-4">01</span>
            <h3 className="text-lg font-bold text-[var(--dark)] mb-2">Safe Discovery</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Target URLs undergo strict SSRF validation before running controlled HTTP and DOM inspection passes.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
            <span className="font-mono text-2xl font-black text-[var(--muted)]/50 block mb-4">02</span>
            <h3 className="text-lg font-bold text-[var(--dark)] mb-2">Evidence-First</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Every finding includes reproducible observations, exact header values, affected tags, and why it matters.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
            <span className="font-mono text-2xl font-black text-[var(--muted)]/50 block mb-4">03</span>
            <h3 className="text-lg font-bold text-[var(--dark)] mb-2">AI-Ready Export</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Export an actionable <code className="text-[11px] font-bold">issues.md</code> artifact directly feedable to Gemini, Claude, or GitHub Issues.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30 backdrop-blur-sm">
            <span className="font-mono text-2xl font-black text-[var(--muted)]/50 block mb-4">04</span>
            <h3 className="text-lg font-bold text-[var(--dark)] mb-2">Fix Verification</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Deploy your fix and hit Rescan. Mola automatically highlights resolved vs remaining issues.
            </p>
          </div>
        </div>
      </section>

      {/* Feature Capabilities Bento */}
      <section id="features" className="w-full max-w-5xl mx-auto px-6 py-20 border-t border-[var(--border)]">
        <div className="mb-12">
          <p className="text-xs font-extrabold uppercase tracking-widest text-[var(--muted)] mb-2">Capabilities</p>
          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-[var(--dark)]">
            Built for Developers Who Hate Fluff
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30">
            <Shield className="w-6 h-6 text-[var(--dark)] mb-3" />
            <h3 className="font-bold text-base text-[var(--dark)] mb-2">Zero Vanity Scores</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              No arbitrary 0–100 badges that provide false security. Clear, evidence-backed priorities sorted by impact.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30">
            <Cpu className="w-6 h-6 text-[var(--dark)] mb-3" />
            <h3 className="font-bold text-base text-[var(--dark)] mb-2">Technology Fingerprinting</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Instantly detects frameworks (Next.js, React, Nuxt), CDN edge hosts (Cloudflare, Vercel), and CMS software.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[var(--border)] bg-white/30">
            <Code2 className="w-6 h-6 text-[var(--dark)] mb-3" />
            <h3 className="font-bold text-base text-[var(--dark)] mb-2">Ready-To-Use Code Fixes</h3>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Each recommendation includes sample Nginx configs, CSP directives, and HTML snippets ready to copy into your repository.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
