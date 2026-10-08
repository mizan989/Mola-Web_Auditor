import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runWebsiteAudit } from "../server/orchestrator.ts";
import { validateUrlAsync } from "../server/validators/url.ts";
import { compareAuditResults } from "../lib/compare.ts";
import type { ScanResult } from "../types/audit.ts";

describe("Phase 0 — Audit Workflow & Orchestrator Verification", () => {
  it("rejects invalid, malformed, or private SSRF targets before network execution", async () => {
    // Missing protocol / invalid URL
    await assert.rejects(
      async () => {
        await runWebsiteAudit({ url: "not-a-valid-domain" });
      },
      {
        message: /Hostname must include a valid top-level domain|Invalid URL/,
      }
    );

    // Localhost SSRF
    await assert.rejects(
      async () => {
        await runWebsiteAudit({ url: "http://localhost:3000" });
      },
      {
        message: /Scanning local, loopback, or cloud metadata endpoints is prohibited|Port '3000' is not permitted/,
      }
    );

    // Private IP SSRF
    await assert.rejects(
      async () => {
        await runWebsiteAudit({ url: "http://192.168.1.1" });
      },
      {
        message: /private or reserved network IP address/,
      }
    );
  });

  it("verifies public URL validation allows standard HTTPS domains", async () => {
    const res = await validateUrlAsync("https://example.com");
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.normalizedUrl, "https://example.com/");
    assert.strictEqual(res.hostname, "example.com");
    assert.ok(Array.isArray(res.resolvedAddresses) && res.resolvedAddresses.length > 0);
  });

  it("executes a live Quick Scan against a public website with valid structure", async () => {
    const result = await runWebsiteAudit({
      url: "https://example.com",
      mode: "quick",
    });

    // Check base envelope fields
    assert.ok(result.scanId.startsWith("mola-"));
    assert.strictEqual(result.scanMode, "quick");
    assert.strictEqual(result.hostname, "example.com");
    assert.ok(result.scanDurationMs >= 0);
    assert.ok(result.status === "completed" || result.status === "partial");

    // Check summary structure
    assert.ok(typeof result.summary.totalFindings === "number");
    assert.ok(typeof result.summary.highCount === "number");
    assert.ok(typeof result.summary.mediumCount === "number");
    assert.ok(typeof result.summary.lowCount === "number");
    assert.ok(typeof result.summary.passedCount === "number");

    // Check findings list structure
    assert.ok(Array.isArray(result.findings));
    for (const f of result.findings) {
      assert.ok(f.id, "finding must have an ID");
      assert.ok(f.title, "finding must have a title");
      assert.ok(f.category, "finding must have a category");
      assert.ok(f.severity, "finding must have a severity");
      assert.ok(f.priority, "finding must have a priority");
      assert.ok(f.evidence !== undefined, "finding must have evidence");
      assert.ok(f.whyItMatters, "finding must explain why it matters");
      assert.ok(f.recommendation, "finding must include recommendation");
    }

    // Check passed checks structure
    assert.ok(Array.isArray(result.passedChecks));
    for (const p of result.passedChecks) {
      assert.ok(p.id, "passed check must have an ID");
      assert.ok(p.category, "passed check must have a category");
      assert.ok(p.title, "passed check must have a title");
      assert.ok(p.detail, "passed check must have a detail");
    }

    // Check HTTP inspection telemetry
    assert.ok(result.httpInfo.statusCode > 0);
    assert.ok(result.httpInfo.headers);
    assert.ok(result.httpInfo.protocol);
    assert.ok(Array.isArray(result.httpInfo.redirectChain));

    // Check Performance, SEO, and Accessibility summaries
    assert.ok(result.performanceMetrics);
    assert.ok(result.seoData);
    assert.ok(result.accessibilitySummary);
  });

  it("executes a live Deep Scan against a public website with valid structure", async () => {
    const result = await runWebsiteAudit({
      url: "https://example.com",
      mode: "deep",
    });

    assert.strictEqual(result.scanMode, "deep");
    assert.ok(result.findings.length > 0);
    assert.ok(result.passedChecks.length > 0);
  });

  it("verifies fix verification loop correctly compares sequential scans", () => {
    const scan1: ScanResult = {
      scanId: "mola-1",
      targetUrl: "https://example.com",
      finalUrl: "https://example.com/",
      hostname: "example.com",
      scanTimestamp: "2026-10-08T09:00:00Z",
      scanDurationMs: 300,
      scanMode: "quick",
      status: "completed",
      completeness: "full",
      summary: {
        totalFindings: 2,
        highCount: 1,
        mediumCount: 1,
        lowCount: 0,
        passedCount: 5,
        categoryCounts: {
          security: 1,
          performance: 1,
          seo: 0,
          accessibility: 0,
          "best-practices": 0,
        },
      },
      findings: [
        {
          id: "sec-hsts-missing",
          category: "security",
          severity: "high",
          priority: "critical",
          title: "Missing HSTS",
          description: "Strict-Transport-Security header is missing",
          whyItMatters: "Prevents SSL stripping",
          evidence: "Header absent",
          affectedTarget: "HTTPS Response Header",
          recommendation: "Add Strict-Transport-Security header",
        },
        {
          id: "perf-gzip-missing",
          category: "performance",
          severity: "medium",
          priority: "fix-first",
          title: "Missing compression",
          description: "No compression header",
          whyItMatters: "Increases bandwidth",
          evidence: "content-encoding absent",
          affectedTarget: "HTTP Response",
          recommendation: "Enable brotli or gzip",
        },
      ],
      passedChecks: [],
      technologies: [],
      httpInfo: {
        statusCode: 200,
        statusText: "OK",
        protocol: "HTTP/1.1 (TLS)",
        responseTimeMs: 120,
        contentLength: 1024,
        contentType: "text/html",
        isHttps: true,
        redirectChain: ["https://example.com/"],
        headers: {},
      },
      performanceMetrics: {
        ttfbMs: 120,
        totalPayloadKb: 1,
        compression: null,
        cacheControl: null,
        scriptsCount: 0,
        stylesheetsCount: 0,
        imagesCount: 0,
      },
      seoData: {
        title: "Example",
        titleLength: 7,
        metaDescription: null,
        descriptionLength: 0,
        canonicalUrl: null,
        robots: null,
        ogTitle: null,
        ogImage: null,
        h1Count: 1,
        headings: [{ level: 1, text: "Example Domain" }],
      },
      accessibilitySummary: {
        imagesTotal: 0,
        imagesMissingAlt: 0,
        missingAltElements: [],
        hasLang: true,
        lang: "en",
        hasMainLandmark: false,
        hasHeaderLandmark: false,
        inputsMissingLabel: 0,
      },
    };

    // Scan 2 resolves HSTS, but still has compression issue
    const scan2: ScanResult = {
      ...scan1,
      scanId: "mola-2",
      scanTimestamp: "2026-10-08T09:05:00Z",
      findings: [scan1.findings[1]], // only compression remaining
    };

    const comp = compareAuditResults(scan1, scan2);
    assert.strictEqual(comp.resolvedFindings.length, 1);
    assert.strictEqual(comp.resolvedFindings[0].id, "sec-hsts-missing");
    assert.strictEqual(comp.remainingFindings.length, 1);
    assert.strictEqual(comp.remainingFindings[0].id, "perf-gzip-missing");
    assert.strictEqual(comp.newFindings.length, 0);
  });
});
