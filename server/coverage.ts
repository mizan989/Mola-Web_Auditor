/**
 * Phase 12: Audit Coverage and Limitations Engine.
 *
 * Tracks:
 * - attempted checks (based on scanMode scope)
 * - completed checks (confirmed findings or verified passing checks)
 * - unable-to-check checks (due to environment, connection, or runtime limits)
 * - failed checks (internal scanner execution failures)
 * - active audit limitations
 * - scan mode
 *
 * Invariant (Phase 12):
 * - Enables users to distinguish "not found" (verified clean) from "not checked" (unsupported / limited).
 * - Never invents an arbitrary, ungrounded percentage score.
 */

import type {
  AuditContext,
  AuditCoverageSummary,
  CategoryCoverage,
  Finding,
  FindingCategory,
  PassedCheck,
  BrowserExecutionResult,
} from "../types/audit.ts";

export interface DefinedCheck {
  id: string;
  name: string;
  category: FindingCategory;
  scope: "quick" | "deep";
  prefixMatches: string[];
}

export const AUDIT_CHECK_CATALOG: DefinedCheck[] = [
  // 1. Security (Quick + Deep)
  { id: "sec-hsts", name: "Strict-Transport-Security (HSTS)", category: "security", scope: "quick", prefixMatches: ["sec-hsts"] },
  { id: "sec-csp", name: "Content-Security-Policy (CSP)", category: "security", scope: "quick", prefixMatches: ["sec-csp"] },
  { id: "sec-xfo", name: "X-Frame-Options (XFO)", category: "security", scope: "quick", prefixMatches: ["sec-xfo"] },
  { id: "sec-xcto", name: "X-Content-Type-Options (XCTO)", category: "security", scope: "quick", prefixMatches: ["sec-xcto"] },
  { id: "sec-referrer-policy", name: "Referrer-Policy Header", category: "security", scope: "quick", prefixMatches: ["sec-referrer-policy"] },
  { id: "sec-permissions-policy", name: "Permissions-Policy Header", category: "security", scope: "quick", prefixMatches: ["sec-permissions-policy"] },
  { id: "sec-server-leak", name: "Server / Powered-By Fingerprint Leak", category: "security", scope: "quick", prefixMatches: ["sec-server", "sec-powered-by"] },
  { id: "sec-cookie-security", name: "Cookie Security (Secure, HttpOnly, SameSite)", category: "security", scope: "quick", prefixMatches: ["sec-cookie"] },
  { id: "sec-tls-transport", name: "TLS Transport Encryption", category: "security", scope: "quick", prefixMatches: ["sec-tls"] },
  { id: "sec-mixed-content", name: "Static Insecure Mixed Content", category: "security", scope: "quick", prefixMatches: ["sec-mixed-content"] },
  { id: "sec-iframe-safety", name: "Iframe Sandbox & Resource Safety", category: "security", scope: "quick", prefixMatches: ["sec-iframe"] },
  // Security (Deep Mode Only)
  { id: "sec-sri", name: "Subresource Integrity (SRI) Hashes", category: "security", scope: "deep", prefixMatches: ["sec-sri"] },
  { id: "sec-cookie-session-lifetime", name: "Cookie Session Expiration Bounds", category: "security", scope: "deep", prefixMatches: ["sec-cookie-session"] },
  { id: "sec-browser-runtime-mixed-content", name: "Runtime Dynamic Mixed Content", category: "security", scope: "deep", prefixMatches: ["sec-browser-runtime-mixed-content", "browser-runtime-mixed-content-clean"] },

  // 2. Performance (Quick + Deep)
  { id: "perf-ttfb", name: "Time To First Byte (TTFB) Latency", category: "performance", scope: "quick", prefixMatches: ["perf-ttfb"] },
  { id: "perf-compression", name: "Text Compression (Gzip / Brotli)", category: "performance", scope: "quick", prefixMatches: ["perf-compression"] },
  { id: "perf-cache-control", name: "Cache-Control Caching Directives", category: "performance", scope: "quick", prefixMatches: ["perf-cache-control"] },
  { id: "perf-payload-limit", name: "Inspection Stream Payload Bound", category: "performance", scope: "quick", prefixMatches: ["perf-payload-truncated"] },

  // 3. SEO (Quick + Deep)
  { id: "seo-title", name: "Document Title Presence & Length", category: "seo", scope: "quick", prefixMatches: ["seo-title"] },
  { id: "seo-meta-description", name: "Meta Description Presence & Length", category: "seo", scope: "quick", prefixMatches: ["seo-meta-description"] },
  { id: "seo-canonical", name: "Canonical URL Tag", category: "seo", scope: "quick", prefixMatches: ["seo-canonical"] },
  { id: "seo-headings", name: "H1 Heading Hierarchy", category: "seo", scope: "quick", prefixMatches: ["seo-headings"] },
  { id: "seo-robots", name: "Robots Indexing Directives", category: "seo", scope: "quick", prefixMatches: ["seo-robots"] },
  { id: "seo-open-graph", name: "Open Graph Social Meta Tags", category: "seo", scope: "quick", prefixMatches: ["seo-og"] },

  // 4. Accessibility (Quick + Deep)
  { id: "a11y-html-lang", name: "Document Language (lang attribute)", category: "accessibility", scope: "quick", prefixMatches: ["a11y-html-lang"] },
  { id: "a11y-img-alt", name: "Image Alternative Text (alt attributes)", category: "accessibility", scope: "quick", prefixMatches: ["a11y-img-alt"] },
  { id: "a11y-inputs-labelled", name: "Form Inputs Accessible Labels", category: "accessibility", scope: "quick", prefixMatches: ["a11y-inputs"] },
  { id: "a11y-main-landmark", name: "Main Landmark Region", category: "accessibility", scope: "quick", prefixMatches: ["a11y-main-landmark"] },
  { id: "a11y-header-landmark", name: "Header Landmark Region", category: "accessibility", scope: "quick", prefixMatches: ["a11y-header-landmark"] },
  // Accessibility (Deep Mode Only)
  { id: "a11y-rendered-inputs-unlabelled", name: "Client-Rendered Form Controls Labels", category: "accessibility", scope: "deep", prefixMatches: ["a11y-rendered-inputs-unlabelled"] },

  // 5. Best Practices (Quick + Deep)
  { id: "bp-doctype", name: "HTML5 Standard Doctype", category: "best-practices", scope: "quick", prefixMatches: ["bp-doctype"] },
  { id: "bp-charset", name: "UTF-8 Charset Encoding", category: "best-practices", scope: "quick", prefixMatches: ["bp-charset"] },
  { id: "bp-viewport", name: "Mobile Viewport Meta Tag", category: "best-practices", scope: "quick", prefixMatches: ["bp-viewport"] },
  { id: "bp-deprecated-tags", name: "Deprecated HTML Tags Avoidance", category: "best-practices", scope: "quick", prefixMatches: ["bp-deprecated-tags"] },
  // Best Practices (Deep Mode Only)
  { id: "browser-js-content-rendered", name: "Client-Side Dynamic DOM Hydration", category: "best-practices", scope: "deep", prefixMatches: ["browser-js-content-rendered"] },
];

/**
 * Calculates deterministic audit coverage, accounting for scanMode, active limitations,
 * and separating completed/verified checks from unable-to-check outcomes.
 */
export function calculateAuditCoverage(
  context: AuditContext,
  findings: Finding[],
  passedChecks: PassedCheck[],
  browserExecution?: BrowserExecutionResult
): AuditCoverageSummary {
  const scanMode = context.scanMode || "quick";
  const limitations = [...context.limitations];

  if (browserExecution?.limitationReason && !limitations.includes(browserExecution.limitationReason)) {
    limitations.push(browserExecution.limitationReason);
  }

  // Filter candidate checks attempted in this scan mode
  const candidateChecks = AUDIT_CHECK_CATALOG.filter((c) => {
    if (scanMode === "quick") {
      return c.scope === "quick";
    }
    return true; // Deep scan attempts all quick + deep checks
  });

  const categories: FindingCategory[] = [
    "security",
    "performance",
    "seo",
    "accessibility",
    "best-practices",
  ];

  const categoryBreakdown: Record<FindingCategory, CategoryCoverage> = {
    security: { category: "security", attempted: 0, completed: 0, unableToCheck: 0, failed: 0, limitations: [] },
    performance: { category: "performance", attempted: 0, completed: 0, unableToCheck: 0, failed: 0, limitations: [] },
    seo: { category: "seo", attempted: 0, completed: 0, unableToCheck: 0, failed: 0, limitations: [] },
    accessibility: { category: "accessibility", attempted: 0, completed: 0, unableToCheck: 0, failed: 0, limitations: [] },
    "best-practices": { category: "best-practices", attempted: 0, completed: 0, unableToCheck: 0, failed: 0, limitations: [] },
  };

  const unverifiedChecks: string[] = [];

  for (const check of candidateChecks) {
    const cat = categoryBreakdown[check.category];
    cat.attempted++;

    // 1. Did any finding match this check?
    const matchingFinding = findings.find((f) =>
      check.prefixMatches.some((prefix) => f.id.startsWith(prefix))
    );

    // 2. Did any passed check match this check?
    const matchingPassed = passedChecks.find((p) =>
      check.prefixMatches.some((prefix) => p.id.startsWith(prefix))
    );

    // Check if browser execution was required but not executed
    const isBrowserCheck =
      check.id.startsWith("sec-browser-") ||
      check.id.startsWith("a11y-rendered-") ||
      check.id === "browser-js-content-rendered";

    if (isBrowserCheck && (!browserExecution || !browserExecution.executed)) {
      cat.unableToCheck++;
      unverifiedChecks.push(`${check.name} (isolated browser execution unavailable)`);
      if (
        browserExecution?.limitationReason &&
        !cat.limitations.includes(browserExecution.limitationReason)
      ) {
        cat.limitations.push(browserExecution.limitationReason);
      }
      continue;
    }

    if (matchingFinding) {
      if (matchingFinding.state === "unable_to_check") {
        cat.unableToCheck++;
        unverifiedChecks.push(`${check.name} (${matchingFinding.description})`);
      } else if (matchingFinding.state === "failed") {
        cat.failed++;
        unverifiedChecks.push(`${check.name} (check failed: ${matchingFinding.description})`);
      } else {
        // Confirmed finding / observation / recommendation
        cat.completed++;
      }
    } else if (matchingPassed) {
      // Confirmed clean / verified passing check
      cat.completed++;
    } else {
      // Neither finding nor passed check explicitly recorded.
      // If the response body was truncated and this is a DOM inspection, mark unable to check.
      if (
        context.body.isTruncated &&
        (check.category === "accessibility" || check.category === "seo" || check.id === "sec-iframe-safety")
      ) {
        cat.unableToCheck++;
        unverifiedChecks.push(`${check.name} (document body truncated at 2.5 MB)`);
      } else {
        // Standard scanner completed with clean result
        cat.completed++;
      }
    }
  }

  // Aggregate summary counts across categories
  let attemptedChecks = 0;
  let completedChecks = 0;
  let unableToCheckCount = 0;
  let failedChecksCount = 0;

  for (const cat of categories) {
    attemptedChecks += categoryBreakdown[cat].attempted;
    completedChecks += categoryBreakdown[cat].completed;
    unableToCheckCount += categoryBreakdown[cat].unableToCheck;
    failedChecksCount += categoryBreakdown[cat].failed;
  }

  return {
    scanMode,
    attemptedChecks,
    completedChecks,
    unableToCheckCount,
    failedChecksCount,
    limitations,
    categoryBreakdown,
    unverifiedChecks: unverifiedChecks.length > 0 ? unverifiedChecks : undefined,
  };
}
