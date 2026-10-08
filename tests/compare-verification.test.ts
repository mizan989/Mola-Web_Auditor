import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compareAuditResults, canCheckRunInRescan } from "../lib/compare.ts";
import { generateVerificationMarkdown } from "../lib/exportMarkdown.ts";
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

function createMockScan(
  findings: Finding[],
  options?: Partial<ScanResult>
): ScanResult {
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
    ...options,
  };
}

describe("Phase 11 — Verification Comparison & Conservative Classification", () => {
  describe("1. Resolved (Fixed) Findings", () => {
    it("identifies resolved findings when a check runs cleanly and issue is absent from new scan", () => {
      const prevFinding = createMockFinding({ id: "sec-hsts-missing" });
      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.resolvedFindings.length, 1);
      assert.strictEqual(comp.resolvedFindings[0].id, "sec-hsts-missing");
      assert.strictEqual(comp.remainingFindings.length, 0);
      assert.strictEqual(comp.changedFindings.length, 0);
      assert.strictEqual(comp.newFindings.length, 0);
      assert.strictEqual(comp.unableToVerifyFindings?.length, 0);

      const diff = comp.diffs?.find((d) => d.findingId === "sec-hsts-missing");
      assert.strictEqual(diff?.status, "fixed");
      assert.strictEqual(comp.summary?.fixed, 1);
    });
  });

  describe("2. Still Present (Unchanged) Findings", () => {
    it("identifies remaining findings when an issue persists across scans with matching attributes", () => {
      const finding1 = createMockFinding({ id: "sec-hsts-missing" });
      const prevScan = createMockScan([finding1]);
      const currScan = createMockScan([{ ...finding1 }]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.remainingFindings.length, 1);
      assert.strictEqual(comp.remainingFindings[0].id, "sec-hsts-missing");
      assert.strictEqual(comp.resolvedFindings.length, 0);
      assert.strictEqual(comp.changedFindings.length, 0);

      const diff = comp.diffs?.find((d) => d.findingId === "sec-hsts-missing");
      assert.strictEqual(diff?.status, "still_present");
      assert.strictEqual(comp.summary?.stillPresent, 1);
    });

    it("normalizes trailing slashes on URL targets to prevent false mismatches", () => {
      const prevFinding = createMockFinding({
        id: "seo-canonical-broken",
        affectedTarget: "https://example.com/",
      });
      const currFinding = createMockFinding({
        id: "seo-canonical-broken",
        affectedTarget: "https://example.com",
      });

      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([currFinding]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.resolvedFindings.length, 0);
      assert.strictEqual(comp.remainingFindings.length, 1);
      assert.strictEqual(comp.changedFindings.length, 0);
    });
  });

  describe("3. Changed Findings (Material Deltas)", () => {
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
        severity: "medium", // Severity changed
        affectedTarget: "button.cta",
      });

      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([currFinding]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.changedFindings.length, 1);
      assert.strictEqual(comp.changedFindings[0].severity, "medium");

      const diff = comp.diffs?.find((d) => d.findingId === "a11y-contrast-ratio");
      assert.strictEqual(diff?.status, "changed");
      assert.strictEqual(diff?.changes?.severity?.from, "high");
      assert.strictEqual(diff?.changes?.severity?.to, "medium");
      assert.strictEqual(comp.summary?.changed, 1);
    });

    it("detects changed findings when state or confidence changes", () => {
      const prevFinding = createMockFinding({
        id: "sec-cors-wildcard",
        state: "observation",
        confidence: "medium",
      });
      const currFinding = createMockFinding({
        id: "sec-cors-wildcard",
        state: "confirmed",
        confidence: "high",
      });

      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([currFinding]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.changedFindings.length, 1);

      const diff = comp.diffs?.find((d) => d.findingId === "sec-cors-wildcard");
      assert.strictEqual(diff?.status, "changed");
      assert.strictEqual(diff?.changes?.state?.from, "observation");
      assert.strictEqual(diff?.changes?.state?.to, "confirmed");
      assert.strictEqual(diff?.changes?.confidence?.from, "medium");
      assert.strictEqual(diff?.changes?.confidence?.to, "high");
    });

    it("detects changed findings when instancesCount decreases (partial remediation)", () => {
      const prevFinding = createMockFinding({
        id: "a11y-img-alt-missing",
        category: "accessibility",
        instancesCount: 5,
        instances: ["img1", "img2", "img3", "img4", "img5"],
      });
      const currFinding = createMockFinding({
        id: "a11y-img-alt-missing",
        category: "accessibility",
        instancesCount: 2,
        instances: ["img1", "img2"],
      });

      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([currFinding]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.changedFindings.length, 1);

      const diff = comp.diffs?.find((d) => d.findingId === "a11y-img-alt-missing");
      assert.strictEqual(diff?.status, "changed");
      assert.strictEqual(diff?.changes?.instancesCount?.from, 5);
      assert.strictEqual(diff?.changes?.instancesCount?.to, 2);
      assert.match(diff?.changes?.materialDetails || "", /changed from 5 to 2/);
    });

    it("detects changed findings when recommendation or evidence changes", () => {
      const prevFinding = createMockFinding({
        id: "sec-csp-eval",
        evidence: "script-src: 'unsafe-eval'",
        recommendation: "Remove unsafe-eval.",
      });
      const currFinding = createMockFinding({
        id: "sec-csp-eval",
        evidence: "script-src: 'unsafe-eval' 'unsafe-inline'",
        recommendation: "Remove both unsafe-eval and unsafe-inline.",
      });

      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([currFinding]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.changedFindings.length, 1);

      const diff = comp.diffs?.find((d) => d.findingId === "sec-csp-eval");
      assert.strictEqual(diff?.status, "changed");
      assert.strictEqual(diff?.changes?.evidence?.from, "script-src: 'unsafe-eval'");
      assert.match(diff?.changes?.recommendation?.to || "", /both unsafe-eval/);
    });
  });

  describe("4. New Findings Introduced", () => {
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
      assert.strictEqual(comp.newFindings.length, 1);
      assert.strictEqual(comp.newFindings[0].id, "seo-title-missing");

      const diff = comp.diffs?.find((d) => d.findingId === "seo-title-missing");
      assert.strictEqual(diff?.status, "new");
      assert.strictEqual(comp.summary?.new, 1);
    });
  });

  describe("5. Conservative Invariant: Unable to Verify (Never False Fixed)", () => {
    it("never marks findings as fixed if the rescan failed entirely (status: failed)", () => {
      const prevFinding = createMockFinding({ id: "sec-hsts-missing" });
      const prevScan = createMockScan([prevFinding]);
      const failedCurrScan = createMockScan([], {
        status: "failed",
        errorMessage: "Network unreachable",
      });

      const comp = compareAuditResults(prevScan, failedCurrScan);
      assert.strictEqual(
        comp.resolvedFindings.length,
        0,
        "Must NOT declare finding fixed when rescan failed"
      );
      assert.strictEqual(comp.unableToVerifyFindings?.length, 1);
      assert.strictEqual(comp.unableToVerifyFindings?.[0].id, "sec-hsts-missing");

      const diff = comp.diffs?.find((d) => d.findingId === "sec-hsts-missing");
      assert.strictEqual(diff?.status, "unable_to_verify");
      assert.match(diff?.reason || "", /rescan failed/i);
      assert.strictEqual(comp.summary?.unableToVerify, 1);
      assert.strictEqual(comp.summary?.fixed, 0);
    });

    it("never marks findings as fixed if the rescan had HTTP status code 0 (connection error)", () => {
      const prevFinding = createMockFinding({ id: "sec-cookie-insecure" });
      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([], {
        httpInfo: {
          statusCode: 0,
          statusText: "Connection Refused",
          protocol: "HTTP/1.1",
          responseTimeMs: 0,
          contentLength: 0,
          contentType: "",
          isHttps: false,
          redirectChain: [],
          headers: {},
        },
      });

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.resolvedFindings.length, 0);
      assert.strictEqual(comp.unableToVerifyFindings?.length, 1);

      const diff = comp.diffs?.find((d) => d.findingId === "sec-cookie-insecure");
      assert.strictEqual(diff?.status, "unable_to_verify");
      assert.match(diff?.reason || "", /unreachable/i);
    });

    it("never marks Deep Scan findings as fixed if rescan was downgraded to Quick Scan mode", () => {
      const deepFinding = createMockFinding({
        id: "sec-sri-missing",
        category: "security",
        title: "External Scripts Lack Subresource Integrity (SRI)",
      });

      const prevDeepScan = createMockScan([deepFinding], { scanMode: "deep" });
      const currQuickScan = createMockScan([], { scanMode: "quick" });

      const comp = compareAuditResults(prevDeepScan, currQuickScan);
      assert.strictEqual(
        comp.resolvedFindings.length,
        0,
        "Deep scan check must not be marked fixed when rescan only performed Quick scan"
      );
      assert.strictEqual(comp.unableToVerifyFindings?.length, 1);
      assert.strictEqual(comp.unableToVerifyFindings?.[0].id, "sec-sri-missing");

      const diff = comp.diffs?.find((d) => d.findingId === "sec-sri-missing");
      assert.strictEqual(diff?.status, "unable_to_verify");
      assert.match(diff?.reason || "", /Quick Scan mode/);
    });

    it("never marks browser-rendered findings as fixed if browser execution was unconfigured/disabled in rescan", () => {
      const browserFinding = createMockFinding({
        id: "a11y-rendered-inputs-unlabelled",
        category: "accessibility",
        title: "Client-Rendered Form Controls Missing Accessible Labels",
        structuredEvidence: {
          observation: "Rendered input without label",
          evidenceType: "browser-a11y-inspection",
        },
      });

      const prevScan = createMockScan([browserFinding], {
        scanMode: "deep",
        browserExecution: {
          isSupported: true,
          executed: true,
          renderedDomByteLength: 5000,
        },
      });

      const currScan = createMockScan([], {
        scanMode: "deep",
        browserExecution: {
          isSupported: false,
          executed: false,
          limitationReason:
            "Isolated browser execution is unavailable or unconfigured in this runtime environment.",
        },
      });

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(
        comp.resolvedFindings.length,
        0,
        "Browser finding must not be marked fixed when browser execution did not run"
      );
      assert.strictEqual(comp.unableToVerifyFindings?.length, 1);

      const diff = comp.diffs?.find((d) => d.findingId === "a11y-rendered-inputs-unlabelled");
      assert.strictEqual(diff?.status, "unable_to_verify");
      assert.match(diff?.reason || "", /browser execution/i);
    });

    it("classifies findings with state unable_to_check in rescan as unable_to_verify", () => {
      const prevFinding = createMockFinding({ id: "sec-tls-unencrypted" });
      const currFinding = createMockFinding({
        id: "sec-tls-unencrypted",
        state: "unable_to_check",
      });

      const prevScan = createMockScan([prevFinding]);
      const currScan = createMockScan([currFinding]);

      const comp = compareAuditResults(prevScan, currScan);
      assert.strictEqual(comp.remainingFindings.length, 0);
      assert.strictEqual(comp.unableToVerifyFindings?.length, 1);

      const diff = comp.diffs?.find((d) => d.findingId === "sec-tls-unencrypted");
      assert.strictEqual(diff?.status, "unable_to_verify");
    });
  });

  describe("6. Markdown Export of Verification Comparison", () => {
    it("formats summary, changes, and unable_to_verify sections in generated markdown", () => {
      const prevFinding = createMockFinding({
        id: "sec-hsts-missing",
        title: "HSTS Header Missing",
      });
      const changedFinding = createMockFinding({
        id: "a11y-img-alt-missing",
        title: "Images Missing alt Attributes",
        severity: "medium",
        instancesCount: 1,
      });
      const browserFinding = createMockFinding({
        id: "sec-browser-runtime-mixed-content",
        title: "Runtime Insecure Mixed Content Fetched by JavaScript",
      });

      const prevScan = createMockScan([prevFinding, changedFinding, browserFinding], {
        scanMode: "deep",
        browserExecution: { isSupported: true, executed: true },
      });

      // In rescan: HSTS fixed, a11y severity changed, browser scan was disabled
      const currScan = createMockScan(
        [
          {
            ...changedFinding,
            severity: "low",
            instancesCount: 0,
          },
        ],
        {
          scanMode: "deep",
          browserExecution: {
            isSupported: false,
            executed: false,
            limitationReason: "Browser scan disabled",
          },
        }
      );

      const comp = compareAuditResults(prevScan, currScan);
      const md = generateVerificationMarkdown(comp);

      assert.match(md, /# Fix Verification Report/);
      assert.match(md, /🟢 Resolved \(Fixed\): \*\*1\*\*/);
      assert.match(md, /🔵 Changed Status: \*\*1\*\*/);
      assert.match(md, /⚪ Unable to Verify: \*\*1\*\*/);
      assert.match(md, /### 🟢 Resolved Issues \(Fixed\)/);
      assert.match(md, /HSTS Header Missing/);
      assert.match(md, /### 🔵 Changed Status/);
      assert.match(md, /Images Missing alt Attributes/);
      assert.match(md, /Severity: medium → low/);
      assert.match(md, /### ⚪ Unable to Verify/);
      assert.match(md, /Runtime Insecure Mixed Content/);
      assert.match(md, /Browser scan disabled/);
    });
  });
});
