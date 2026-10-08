import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { calculateAuditCoverage, AUDIT_CHECK_CATALOG } from "../server/coverage.ts";
import { buildAuditContext } from "../server/context.ts";
import { runWebsiteAudit } from "../server/orchestrator.ts";
import { generateIssuesMarkdown } from "../lib/exportMarkdown.ts";
import type { AuditContext, Finding, PassedCheck, ScanResult } from "../types/audit.ts";

function createMockContext(overrides?: Partial<AuditContext>): AuditContext {
  const html = `<!DOCTYPE html><html lang="en"><head><title>Test Page</title><meta name="description" content="Valid test description"></head><body><h1>Heading</h1></body></html>`;
  return buildAuditContext({
    targetUrl: "https://example.com",
    finalUrl: "https://example.com/",
    scanMode: overrides?.scanMode || "quick",
    scanId: "test-scan-coverage",
    startTime: Date.now() - 100,
    httpResult: {
      finalUrl: "https://example.com/",
      info: {
        statusCode: 200,
        statusText: "OK",
        protocol: "HTTP/1.1 (TLS)",
        responseTimeMs: 75,
        contentLength: html.length,
        contentType: "text/html; charset=utf-8",
        isHttps: true,
        redirectChain: ["https://example.com/"],
        headers: { "content-type": "text/html" },
      },
      htmlText: html,
      rawHeaders: { "content-type": "text/html" },
      isTruncated: false,
    },
    ...overrides,
  });
}

describe("Phase 12 — Audit Coverage and Limitations Engine", () => {
  describe("1. Quick Scan Check Coverage", () => {
    it("tracks exact Quick Scan scope without including unattempted Deep Scan checks", () => {
      const context = createMockContext({ scanMode: "quick" });
      const findings: Finding[] = [
        {
          id: "sec-hsts-missing",
          category: "security",
          severity: "high",
          priority: "critical",
          state: "confirmed",
          confidence: "high",
          title: "HSTS Missing",
          description: "Missing HSTS header",
          whyItMatters: "Security",
          evidence: "Missing",
          recommendation: "Add HSTS",
        },
      ];
      const passedChecks: PassedCheck[] = [
        {
          id: "sec-csp-valid",
          category: "security",
          state: "confirmed",
          confidence: "high",
          title: "CSP Valid",
          detail: "CSP header present",
        },
      ];

      const coverage = calculateAuditCoverage(context, findings, passedChecks);

      assert.strictEqual(coverage.scanMode, "quick");
      assert.ok(coverage.attemptedChecks > 0);
      assert.strictEqual(
        coverage.attemptedChecks,
        AUDIT_CHECK_CATALOG.filter((c) => c.scope === "quick").length
      );
      assert.strictEqual(coverage.unableToCheckCount, 0);
      assert.strictEqual(coverage.failedChecksCount, 0);
      assert.strictEqual(coverage.completedChecks, coverage.attemptedChecks);
      assert.strictEqual(coverage.unverifiedChecks, undefined);
    });
  });

  describe("2. Deep Scan Coverage & Browser Limitations", () => {
    it("distinguishes uncompleted browser checks as unable_to_check when browser is unavailable", () => {
      const context = createMockContext({
        scanMode: "deep",
        limitations: [
          "Isolated browser execution is unavailable or unconfigured in this runtime environment.",
        ],
      });

      const coverage = calculateAuditCoverage(context, [], [], {
        isSupported: false,
        executed: false,
        limitationReason:
          "Isolated browser execution is unavailable or unconfigured in this runtime environment.",
      });

      assert.strictEqual(coverage.scanMode, "deep");
      assert.ok(coverage.attemptedChecks > AUDIT_CHECK_CATALOG.filter((c) => c.scope === "quick").length);
      assert.ok(coverage.unableToCheckCount > 0);
      assert.ok(coverage.completedChecks < coverage.attemptedChecks);
      assert.ok(coverage.unverifiedChecks && coverage.unverifiedChecks.length > 0);

      // Verify browser checks are specifically flagged in unverifiedChecks
      assert.ok(
        coverage.unverifiedChecks.some((u) => u.includes("browser"))
      );

      // Verify category breakdown tracks unableToCheck for security, a11y, and best-practices
      assert.ok(coverage.categoryBreakdown.security.unableToCheck > 0);
      assert.ok(coverage.categoryBreakdown.accessibility.unableToCheck > 0);
      assert.ok(coverage.categoryBreakdown["best-practices"].unableToCheck > 0);
    });

    it("marks browser checks as completed when browser runner successfully executes", () => {
      const context = createMockContext({ scanMode: "deep" });
      const browserPassedChecks: PassedCheck[] = [
        {
          id: "browser-runtime-mixed-content-clean",
          category: "security",
          state: "not_detected",
          confidence: "high",
          title: "Zero Runtime Mixed Content Observed",
          detail: "All dynamic requests were HTTPS",
        },
        {
          id: "browser-js-content-rendered",
          category: "best-practices",
          state: "confirmed",
          confidence: "high",
          title: "Dynamic Content Rendered",
          detail: "Post-hydration DOM captured",
        },
      ];

      const coverage = calculateAuditCoverage(context, [], browserPassedChecks, {
        isSupported: true,
        executed: true,
        renderedDomByteLength: 4500,
      });

      assert.strictEqual(coverage.scanMode, "deep");
      assert.strictEqual(coverage.unableToCheckCount, 0);
      assert.strictEqual(coverage.completedChecks, coverage.attemptedChecks);
    });
  });

  describe("3. Truncated Payload Limitations", () => {
    it("flags downstream DOM checks as unable_to_check when document is truncated at 2.5 MB", () => {
      const context = createMockContext({
        scanMode: "quick",
        limitations: [
          "Document payload exceeded the 2.5 MB inspection limit and was safely capped; downstream DOM nodes were truncated.",
        ],
      });
      context.body.isTruncated = true;

      const coverage = calculateAuditCoverage(context, [], []);

      assert.ok(coverage.unableToCheckCount > 0);
      assert.ok(coverage.unverifiedChecks && coverage.unverifiedChecks.length > 0);
      assert.ok(
        coverage.unverifiedChecks.some((u) => u.includes("truncated at 2.5 MB"))
      );
    });
  });

  describe("4. No Invented Percentages & Rigorous Methodology", () => {
    it("provides discrete integer counts and does not expose a fabricated percentage", () => {
      const context = createMockContext({ scanMode: "quick" });
      const coverage = calculateAuditCoverage(context, [], []);

      assert.strictEqual(typeof coverage.attemptedChecks, "number");
      assert.strictEqual(typeof coverage.completedChecks, "number");
      assert.strictEqual(typeof coverage.unableToCheckCount, "number");
      assert.strictEqual(typeof coverage.failedChecksCount, "number");

      // Verify no misleading percentage property exists on the coverage summary
      assert.strictEqual((coverage as unknown as Record<string, unknown>).score, undefined);
      assert.strictEqual((coverage as unknown as Record<string, unknown>).percentage, undefined);
    });
  });

  describe("5. Markdown Export Integration", () => {
    it("renders compact Audit Scope & Check Coverage table with limitations and unverified checks", () => {
      const mockResult: ScanResult = {
        scanId: "mola-p12-test",
        targetUrl: "https://example.com",
        finalUrl: "https://example.com/",
        hostname: "example.com",
        scanTimestamp: new Date().toISOString(),
        scanDurationMs: 400,
        scanMode: "deep",
        status: "completed",
        completeness: "full",
        summary: {
          totalFindings: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          passedCount: 22,
          categoryCounts: {
            security: 0,
            performance: 0,
            seo: 0,
            accessibility: 0,
            "best-practices": 0,
          },
        },
        findings: [],
        passedChecks: [],
        technologies: [],
        httpInfo: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 60,
          contentLength: 2000,
          contentType: "text/html",
          isHttps: true,
          redirectChain: ["https://example.com/"],
          headers: {},
        },
        performanceMetrics: {
          ttfbMs: 60,
          totalPayloadKb: 2,
          compression: "gzip",
          cacheControl: "public, max-age=3600",
          scriptsCount: 1,
          stylesheetsCount: 1,
          imagesCount: 0,
        },
        seoData: {
          title: "Title",
          titleLength: 5,
          metaDescription: null,
          descriptionLength: 0,
          canonicalUrl: null,
          robots: null,
          ogTitle: null,
          ogImage: null,
          h1Count: 1,
          headings: [],
        },
        accessibilitySummary: {
          imagesTotal: 0,
          imagesMissingAlt: 0,
          missingAltElements: [],
          hasLang: true,
          lang: "en",
          hasMainLandmark: true,
          hasHeaderLandmark: true,
          inputsMissingLabel: 0,
        },
        limitations: [
          "Isolated browser execution is unavailable or unconfigured in this runtime environment.",
        ],
        coverage: {
          scanMode: "deep",
          attemptedChecks: 28,
          completedChecks: 25,
          unableToCheckCount: 3,
          failedChecksCount: 0,
          limitations: [
            "Isolated browser execution is unavailable or unconfigured in this runtime environment.",
          ],
          categoryBreakdown: {
            security: { category: "security", attempted: 14, completed: 13, unableToCheck: 1, failed: 0, limitations: [] },
            performance: { category: "performance", attempted: 4, completed: 4, unableToCheck: 0, failed: 0, limitations: [] },
            seo: { category: "seo", attempted: 6, completed: 6, unableToCheck: 0, failed: 0, limitations: [] },
            accessibility: { category: "accessibility", attempted: 6, completed: 5, unableToCheck: 1, failed: 0, limitations: [] },
            "best-practices": { category: "best-practices", attempted: 5, completed: 4, unableToCheck: 1, failed: 0, limitations: [] },
          },
          unverifiedChecks: [
            "Runtime Dynamic Mixed Content (isolated browser execution unavailable)",
            "Client-Rendered Form Controls Labels (isolated browser execution unavailable)",
            "Client-Side Dynamic DOM Hydration (isolated browser execution unavailable)",
          ],
        },
      };

      const md = generateIssuesMarkdown(mockResult);

      assert.match(md, /## Audit Scope & Check Coverage/);
      assert.match(md, /Checks Attempted\*\* \| \*\*28\*\*/);
      assert.match(md, /Checks Completed\*\* \| \*\*25\*\*/);
      assert.match(md, /Unable to Check\*\* \| \*\*3\*\*/);
      assert.match(md, /### Active Audit Limitations/);
      assert.match(md, /Isolated browser execution is unavailable/);
      assert.match(md, /### Checks Unable to Run \(Not Evaluated\)/);
      assert.match(md, /Runtime Dynamic Mixed Content/);
    });
  });

  describe("6. Live Orchestrator Execution Coverage", () => {
    it("attaches calculated coverage to ScanResult in runWebsiteAudit", async () => {
      const result = await runWebsiteAudit({
        url: "https://example.com",
        mode: "quick",
      });

      assert.ok(result.coverage, "ScanResult must include coverage summary");
      assert.strictEqual(result.coverage.scanMode, "quick");
      assert.ok(result.coverage.attemptedChecks > 0);
      assert.strictEqual(typeof result.coverage.completedChecks, "number");
      assert.strictEqual(typeof result.coverage.unableToCheckCount, "number");
      assert.ok(result.coverage.categoryBreakdown.security);
      assert.ok(result.coverage.categoryBreakdown.performance);
      assert.ok(result.coverage.categoryBreakdown.seo);
      assert.ok(result.coverage.categoryBreakdown.accessibility);
      assert.ok(result.coverage.categoryBreakdown["best-practices"]);
    });
  });
});
