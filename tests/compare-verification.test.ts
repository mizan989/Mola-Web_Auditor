import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compareAuditResults } from "../lib/compare.ts";
import type { ScanResult, Finding } from "../types/audit.ts";

function createMockFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "sec-hsts-missing",
    category: "security",
    severity: "high",
    priority: "critical",
    state: "confirmed",
    confidence: "high",
    title: "Strict-Transport-Security (HSTS) Header Missing",
    description: "The server did not send an HSTS header.",
    whyItMatters: "Allows SSL stripping attacks.",
    evidence: "HSTS header absent",
    affectedTarget: "HTTPS Response Headers",
    recommendation: "Add Strict-Transport-Security header.",
    ...overrides,
  };
}

function createMockScan(findings: Finding[]): ScanResult {
  return {
    scanId: "scan-mock-1",
    targetUrl: "https://example.com",
    finalUrl: "https://example.com/",
    hostname: "example.com",
    scanTimestamp: new Date().toISOString(),
    scanMode: "quick",
    completeness: "full",
    summary: {
      highCount: findings.filter((f) => f.severity === "high").length,
      mediumCount: findings.filter((f) => f.severity === "medium").length,
      lowCount: findings.filter((f) => f.severity === "low").length,
      totalFindings: findings.length,
      passedCount: 10,
      categoryCounts: {
        security: 0,
        performance: 0,
        seo: 0,
        accessibility: 0,
        "best-practices": 0,
      },
    },
    scanDurationMs: 250,
    status: "completed",
    findings,
    passedChecks: [],
    technologies: [],
    httpInfo: {
      statusCode: 200,
      statusText: "OK",
      protocol: "HTTP/1.1 (TLS)",
      responseTimeMs: 45,
      contentLength: 2048,
      contentType: "text/html",
      isHttps: true,
      redirectChain: ["https://example.com/"],
      headers: {},
    },
    performanceMetrics: {
      ttfbMs: 45,
      totalPayloadKb: 2,
      compression: null,
      cacheControl: null,
      scriptsCount: 0,
      stylesheetsCount: 0,
      imagesCount: 0,
    },
    seoData: {
      title: "Test",
      titleLength: 4,
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
  };
}

describe("Verification Comparison (ISSUE-025, ISSUE-050)", () => {
  it("identifies resolved findings when an issue is absent from the new scan", () => {
    const prevFinding = createMockFinding({ id: "sec-hsts-missing" });
    const prevScan = createMockScan([prevFinding]);
    const currScan = createMockScan([]);

    const comp = compareAuditResults(prevScan, currScan);
    assert.equal(comp.resolvedFindings.length, 1);
    assert.equal(comp.resolvedFindings[0].id, "sec-hsts-missing");
    assert.equal(comp.remainingFindings.length, 0);
    assert.equal(comp.newFindings.length, 0);
  });

  it("identifies remaining findings when an issue persists across scans", () => {
    const finding1 = createMockFinding({ id: "sec-hsts-missing" });
    const prevScan = createMockScan([finding1]);
    const currScan = createMockScan([{ ...finding1 }]);

    const comp = compareAuditResults(prevScan, currScan);
    assert.equal(comp.remainingFindings.length, 1);
    assert.equal(comp.remainingFindings[0].id, "sec-hsts-missing");
    assert.equal(comp.resolvedFindings.length, 0);
    assert.equal(comp.newFindings.length, 0);
  });

  it("does not falsely mark an issue resolved if its instance ID changes but target/rule remain", () => {
    // Both represent the exact same security vulnerability on the same target
    const prevFinding = createMockFinding({
      id: "sec-hsts-missing",
      affectedTarget: "HTTPS Response Headers",
    });
    const currFinding = createMockFinding({
      id: "sec-hsts-missing",
      affectedTarget: "HTTPS Response Headers",
    });

    const prevScan = createMockScan([prevFinding]);
    const currScan = createMockScan([currFinding]);

    const comp = compareAuditResults(prevScan, currScan);
    assert.equal(comp.resolvedFindings.length, 0, "Must not be considered resolved");
    assert.equal(comp.remainingFindings.length, 1, "Must be recognized as still present");
  });

  it("detects new findings introduced in the rescan", () => {
    const prevScan = createMockScan([]);
    const newFinding = createMockFinding({
      id: "seo-title-missing",
      category: "seo",
      title: "Page Title Missing",
      affectedTarget: "<head><title>",
    });
    const currScan = createMockScan([newFinding]);

    const comp = compareAuditResults(prevScan, currScan);
    assert.equal(comp.newFindings.length, 1);
    assert.equal(comp.newFindings[0].id, "seo-title-missing");
  });

  it("detects changed findings when severity changes", () => {
    const prevFinding = createMockFinding({
      id: "a11y-contrast-ratio",
      category: "accessibility",
      severity: "high",
      affectedTarget: "button.cta",
    });
    const currFinding = createMockFinding({
      id: "a11y-contrast-ratio",
      category: "accessibility",
      severity: "medium", // Severity improved
      affectedTarget: "button.cta",
    });

    const prevScan = createMockScan([prevFinding]);
    const currScan = createMockScan([currFinding]);

    const comp = compareAuditResults(prevScan, currScan);
    assert.equal(comp.changedFindings.length, 1);
    assert.equal(comp.changedFindings[0].severity, "medium");
  });
});
