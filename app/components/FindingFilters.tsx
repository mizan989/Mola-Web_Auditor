"use client";

import React from "react";
import { Search, X } from "lucide-react";
import { FindingCategory, FindingSeverity } from "@/types/audit";

interface FindingFiltersProps {
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  selectedSeverity: FindingSeverity | "all";
  setSelectedSeverity: (sev: FindingSeverity | "all") => void;
  selectedCategory: FindingCategory | "all";
  setSelectedCategory: (cat: FindingCategory | "all") => void;
  totalResults: number;
  onClearFilters: () => void;
}

/**
 * Filter and search bar conforming to ISSUE-048.
 * Clearly displays active filters, search scope, and a one-click Clear Filters action.
 */
export function FindingFilters({
  searchQuery,
  setSearchQuery,
  selectedSeverity,
  setSelectedSeverity,
  selectedCategory,
  setSelectedCategory,
  totalResults,
  onClearFilters,
}: FindingFiltersProps) {
  const isFiltered =
    searchQuery.trim().length > 0 ||
    selectedSeverity !== "all" ||
    selectedCategory !== "all";

  return (
    <div
      role="search"
      aria-label="Filter audit findings"
      className="p-4 sm:p-5 rounded-2xl bg-white/40 border border-[var(--border)] mb-6 space-y-3"
    >
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search input */}
        <div className="flex-1 relative">
          <label htmlFor="findings-search" className="sr-only">
            Search findings
          </label>
          <Search className="w-4 h-4 text-[var(--muted)] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            id="findings-search"
            type="search"
            placeholder="Search by issue title, affected resource, or keyword…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-white/60 rounded-xl border border-[var(--border)] text-xs text-[var(--text-primary)] placeholder-[var(--muted)] outline-none focus-visible:ring-2 focus-visible:ring-[var(--deep)]"
          />
        </div>

        {/* Severity selection */}
        <div className="flex flex-wrap items-center gap-1 text-xs" role="group" aria-label="Filter by Severity">
          {(["all", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setSelectedSeverity(sev)}
              className={`px-3 py-1.5 rounded-lg font-bold capitalize transition-all focus-visible:ring-2 focus-visible:ring-[var(--deep)] ${
                selectedSeverity === sev
                  ? "bg-[var(--deep)] text-[var(--white)] shadow-2xs"
                  : "text-[var(--muted)] hover:text-[var(--text-primary)] bg-white/40"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Clear Filters Button & Result count (ISSUE-048) */}
        {isFiltered ? (
          <div className="flex items-center gap-2 self-start md:self-auto">
            <span className="text-xs text-[var(--muted)] font-medium">({totalResults} total)</span>
            <button
              type="button"
              onClick={onClearFilters}
              className="px-2.5 py-1.5 rounded-lg border border-[var(--border)] bg-white/60 text-xs font-semibold text-[var(--muted)] hover:text-[var(--dark)] flex items-center gap-1 transition-all"
              title="Reset all filters and search query"
            >
              <X className="w-3.5 h-3.5" />
              <span>Clear Filters</span>
            </button>
          </div>
        ) : (
          <span className="text-xs text-[var(--muted)] font-medium self-center hidden sm:inline">
            {totalResults} {totalResults === 1 ? "finding" : "findings"}
          </span>
        )}
      </div>

      {/* Category selection */}
      <div className="flex flex-wrap items-center gap-1 text-xs pt-1 border-t border-[var(--border)]/50" role="group" aria-label="Filter by Category">
        <span className="text-[10px] font-extrabold uppercase tracking-wider text-[var(--muted)] mr-1">Category:</span>
        {(["all", "security", "performance", "seo", "accessibility", "best-practices"] as const).map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => setSelectedCategory(cat)}
            className={`px-2.5 py-1 rounded-lg font-semibold capitalize transition-all focus-visible:ring-2 focus-visible:ring-[var(--deep)] ${
              selectedCategory === cat
                ? "bg-[var(--dark)] text-[var(--white)] shadow-2xs"
                : "text-[var(--muted)] hover:text-[var(--text-primary)] bg-white/40"
            }`}
          >
            {cat.replace("-", " ")}
          </button>
        ))}
      </div>
    </div>
  );
}
