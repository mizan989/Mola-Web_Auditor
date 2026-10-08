import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  isBrowserRuntimeSupported,
  executeIsolatedBrowserScan,
  setBrowserRunnerAdapter,
  type BrowserRunnerAdapter,
  BROWSER_TIMEOUT_MS,
} from "../server/browser.ts";
import { buildAuditContext } from "../server/context.ts";
import { runWebsiteAudit } from "../server/orchestrator.ts";
import { generateIssuesMarkdown } from "../lib/exportMarkdown.ts";
import type { AuditContext, ScanResult } from "../types/audit.ts";

function createMockContext(overrides?: {
  targetUrl?: string;
  finalUrl?: string;
  hostname?: string;
  scanMode?: "quick" | "deep";
  isHttps?: boolean;
  html?: string;
}): AuditContext {
  const targetUrl = overrides?.targetUrl || "https://example.com";
  const finalUrl = overrides?.finalUrl || "https://example.com/";
  const staticHtml =
    overrides?.html ??
    `<!DOCTYPE html><html><head><title>Test Page</title></head><body><div id="root"><p>Hello static</p></div></body></html>`;

  return buildAuditContext({
    targetUrl,
    finalUrl,
    scanMode: overrides?.scanMode || "deep",
    scanId: "test-browser-deep-scan-ctx",
    startTime: Date.now() - 100,
    httpResult: {
      finalUrl,
      info: {
        statusCode: 200,
        statusText: "OK",
        protocol: overrides?.isHttps === false ? "HTTP/1.1" : "HTTP/1.1 (TLS)",
        responseTimeMs: 80,
        contentLength: staticHtml.length,
        contentType: "text/html; charset=utf-8",
        isHttps: overrides?.isHttps !== false,
        redirectChain: [targetUrl],
        headers: {
          "content-type": "text/html; charset=utf-8",
        },
      },
      htmlText: staticHtml,
      rawHeaders: {
        "content-type": "text/html; charset=utf-8",
      },
      isTruncated: false,
    },
  });
}

describe("Phase 10 — Isolated Browser Execution for Deep Scan", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    setBrowserRunnerAdapter(null);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    setBrowserRunnerAdapter(null);
  });

  describe("Runtime Availability and Safe Isolation Checks", () => {
    it("reports supported: false with explicit limitation when unconfigured in default environment", async () => {
      delete process.env.DISABLE_BROWSER_SCAN;
      delete process.env.MOLA_BROWSER_EXECUTABLE;
      delete process.env.CHROME_BIN;
      delete process.env.PUPPETEER_EXECUTABLE_PATH;

      const check = await isBrowserRuntimeSupported();
      assert.strictEqual(check.supported, false);
      assert.match(
        check.reason || "",
        /Isolated browser execution is unavailable or unconfigured in this runtime environment/
      );
    });

    it("respects DISABLE_BROWSER_SCAN=true override", async () => {
      process.env.DISABLE_BROWSER_SCAN = "true";
      process.env.MOLA_BROWSER_EXECUTABLE = "/usr/bin/chromium";

      const check = await isBrowserRuntimeSupported();
      assert.strictEqual(check.supported, false);
      assert.match(check.reason || "", /Browser execution explicitly disabled/);
    });

    it("detects configured browser executable path", async () => {
      delete process.env.DISABLE_BROWSER_SCAN;
      process.env.MOLA_BROWSER_EXECUTABLE = "/usr/bin/google-chrome";

      const check = await isBrowserRuntimeSupported();
      assert.strictEqual(check.supported, true);
      assert.strictEqual(check.executablePath, "/usr/bin/google-chrome");
    });
  });

  describe("SSRF Protection for Browser Execution", () => {
    it("blocks browser navigation to private/loopback/metadata destinations", async () => {
      const adapter: BrowserRunnerAdapter = {
        async navigateAndCapture() {
          throw new Error("Should not be called for SSRF target");
        },
      };

      const privateContext = createMockContext({
        targetUrl: "http://127.0.0.1:8080",
        finalUrl: "http://127.0.0.1:8080",
        hostname: "127.0.0.1",
      });

      const result = await executeIsolatedBrowserScan(privateContext, adapter);
      assert.strictEqual(result.executed, false);
      assert.match(result.limitationReason || "", /Browser navigation blocked/);

      const ssrfFinding = result.findings?.find((f) => f.id === "sec-browser-ssrf-blocked");
      assert.ok(ssrfFinding, "Should generate sec-browser-ssrf-blocked finding");
      assert.strictEqual(ssrfFinding.category, "security");
      assert.strictEqual(ssrfFinding.severity, "high");
      assert.strictEqual(ssrfFinding.priority, "critical");
    });
  });

  describe("Dynamic Content and Runtime Observation via Adapter", () => {
    it("detects client-side dynamic rendering and hydrated elements", async () => {
      const renderedHtml = `<!DOCTYPE html><html><head><title>Test Page</title></head><body>
        <div id="root">
          <p>Hello static</p>
          <div class="dynamic-widget"><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div></div>
        </div>
      </body></html>`;

      const adapter: BrowserRunnerAdapter = {
        async navigateAndCapture() {
          return {
            renderedHtml,
            resources: [
              {
                url: "https://example.com/bundle.js",
                resourceType: "script",
                isMixedContent: false,
                isHttps: true,
              },
            ],
            navigationDurationMs: 350,
          };
        },
      };

      const context = createMockContext();
      const result = await executeIsolatedBrowserScan(context, adapter);

      assert.strictEqual(result.isSupported, true);
      assert.strictEqual(result.executed, true);
      assert.strictEqual(result.jsRenderedContentDetected, true);
      assert.ok((result.jsRenderedElementsCount || 0) > 0);

      const renderedCheck = result.passedChecks?.find((p) => p.id === "browser-js-content-rendered");
      assert.ok(renderedCheck, "Should record browser-js-content-rendered passed check");
      assert.strictEqual(renderedCheck.category, "best-practices");
    });

    it("detects client-rendered form controls missing accessible labels", async () => {
      const renderedHtml = `<!DOCTYPE html><html><head><title>Test Page</title></head><body>
        <div id="app">
          <input type="text" placeholder="Enter username" />
          <input type="email" placeholder="Enter email" />
        </div>
      </body></html>`;

      const adapter: BrowserRunnerAdapter = {
        async navigateAndCapture() {
          return {
            renderedHtml,
            resources: [],
            navigationDurationMs: 250,
          };
        },
      };

      const context = createMockContext();
      const result = await executeIsolatedBrowserScan(context, adapter);

      assert.strictEqual(result.executed, true);
      assert.strictEqual(result.renderedA11yIssuesCount, 2);

      const a11yFinding = result.findings?.find((f) => f.id === "a11y-rendered-inputs-unlabelled");
      assert.ok(a11yFinding, "Should generate a11y-rendered-inputs-unlabelled finding");
      assert.strictEqual(a11yFinding.category, "accessibility");
      assert.strictEqual(a11yFinding.severity, "medium");
      assert.strictEqual(a11yFinding.instancesCount, 2);
    });

    it("detects runtime insecure mixed content fetched by client scripts", async () => {
      const renderedHtml = `<!DOCTYPE html><html><body><div>App</div></body></html>`;

      const adapter: BrowserRunnerAdapter = {
        async navigateAndCapture() {
          return {
            renderedHtml,
            resources: [
              {
                url: "http://insecure-cdn.com/analytics.js",
                resourceType: "script",
                isMixedContent: true,
                isHttps: false,
              },
              {
                url: "https://example.com/style.css",
                resourceType: "stylesheet",
                isMixedContent: false,
                isHttps: true,
              },
            ],
            navigationDurationMs: 400,
          };
        },
      };

      const context = createMockContext({
        targetUrl: "https://example.com",
        finalUrl: "https://example.com",
        isHttps: true,
      });

      const result = await executeIsolatedBrowserScan(context, adapter);
      assert.strictEqual(result.executed, true);
      assert.strictEqual(result.runtimeMixedContentCount, 1);

      const mixedFinding = result.findings?.find((f) => f.id === "sec-browser-runtime-mixed-content");
      assert.ok(mixedFinding, "Should detect runtime mixed content");
      assert.strictEqual(mixedFinding.category, "security");
      assert.strictEqual(mixedFinding.severity, "high");
      assert.strictEqual(mixedFinding.priority, "critical");
    });

    it("verifies clean zero mixed content passed check when all dynamic resources are secure", async () => {
      const renderedHtml = `<!DOCTYPE html><html><body><div>App</div></body></html>`;

      const adapter: BrowserRunnerAdapter = {
        async navigateAndCapture() {
          return {
            renderedHtml,
            resources: [
              {
                url: "https://secure-cdn.com/api.json",
                resourceType: "fetch",
                isMixedContent: false,
                isHttps: true,
              },
            ],
            navigationDurationMs: 200,
          };
        },
      };

      const context = createMockContext();
      const result = await executeIsolatedBrowserScan(context, adapter);
      assert.strictEqual(result.executed, true);
      assert.strictEqual(result.runtimeMixedContentCount, 0);

      const cleanCheck = result.passedChecks?.find((p) => p.id === "browser-runtime-mixed-content-clean");
      assert.ok(cleanCheck, "Should produce browser-runtime-mixed-content-clean check");
    });

    it("handles execution timeout or runner crashes gracefully without failing the audit", async () => {
      const adapter: BrowserRunnerAdapter = {
        async navigateAndCapture() {
          throw new Error(`Navigation timed out after ${BROWSER_TIMEOUT_MS}ms`);
        },
      };

      const context = createMockContext();
      const result = await executeIsolatedBrowserScan(context, adapter);

      assert.strictEqual(result.executed, false);
      assert.match(result.limitationReason || "", /timed out/);

      const failFinding = result.findings?.find((f) => f.id === "sec-browser-execution-failed");
      assert.ok(failFinding, "Should record sec-browser-execution-failed finding");
      assert.strictEqual(failFinding.state, "unable_to_check");
      assert.strictEqual(failFinding.confidence, "high");
    });
  });

  describe("Orchestrator Integration & Mode Separation", () => {
    it("keeps Quick Scan lightweight without invoking browser execution", async () => {
      let adapterCalled = false;
      setBrowserRunnerAdapter({
        async navigateAndCapture() {
          adapterCalled = true;
          return { renderedHtml: "", resources: [], navigationDurationMs: 0 };
        },
      });

      const result = await runWebsiteAudit({
        url: "https://example.com",
        mode: "quick",
      });

      assert.strictEqual(result.scanMode, "quick");
      assert.strictEqual(adapterCalled, false, "Quick scan must never call browser runner adapter");
      assert.strictEqual(result.browserExecution, undefined);
    });

    it("includes browser findings and records limitations in Deep Scan", async () => {
      setBrowserRunnerAdapter({
        async navigateAndCapture() {
          return {
            renderedHtml: "<html><body><div><input type='text' /></div></body></html>",
            resources: [],
            navigationDurationMs: 300,
          };
        },
      });

      const result = await runWebsiteAudit({
        url: "https://example.com",
        mode: "deep",
      });

      assert.strictEqual(result.scanMode, "deep");
      assert.ok(result.browserExecution);
      assert.strictEqual(result.browserExecution.executed, true);

      // Verify the dynamic a11y finding was integrated into result.findings
      const dynamicA11y = result.findings.find((f) => f.id === "a11y-rendered-inputs-unlabelled");
      assert.ok(dynamicA11y, "Dynamic a11y finding should be in scanResult.findings");
    });

    it("records explicit limitation when browser is unconfigured in Deep Scan", async () => {
      delete process.env.MOLA_BROWSER_EXECUTABLE;
      delete process.env.CHROME_BIN;
      setBrowserRunnerAdapter(null);

      const result = await runWebsiteAudit({
        url: "https://example.com",
        mode: "deep",
      });

      assert.strictEqual(result.scanMode, "deep");
      assert.ok(result.browserExecution);
      assert.strictEqual(result.browserExecution.executed, false);
      assert.ok(result.limitations && result.limitations.length > 0);
      assert.match(
        result.limitations[0],
        /Isolated browser execution is unavailable or unconfigured in this runtime environment/
      );
    });
  });

  describe("Markdown and Issues Export of Limitations & Diagnostics", () => {
    it("formats Audit Scope & Limitations and Browser Execution Diagnostics in markdown output", () => {
      const mockResult: ScanResult = {
        scanId: "mola-test-p10",
        targetUrl: "https://example.com",
        finalUrl: "https://example.com/",
        hostname: "example.com",
        scanTimestamp: new Date().toISOString(),
        scanDurationMs: 1200,
        scanMode: "deep",
        status: "completed",
        completeness: "full",
        summary: {
          totalFindings: 1,
          highCount: 1,
          mediumCount: 0,
          lowCount: 0,
          passedCount: 1,
          categoryCounts: {
            security: 1,
            performance: 0,
            seo: 0,
            accessibility: 0,
            "best-practices": 0,
          },
        },
        findings: [
          {
            id: "sec-browser-runtime-mixed-content",
            category: "security",
            severity: "high",
            priority: "critical",
            state: "confirmed",
            confidence: "high",
            title: "Runtime Insecure Mixed Content Fetched by JavaScript",
            description: "Insecure subresources requested dynamically.",
            whyItMatters: "Causes browser security warnings.",
            evidence: "http://insecure.test/script.js",
            recommendation: "Use HTTPS exclusively.",
          },
        ],
        passedChecks: [
          {
            id: "browser-js-content-rendered",
            category: "best-practices",
            state: "confirmed",
            confidence: "high",
            title: "Client-Side Dynamic Content Rendered",
            detail: "Hydration completed successfully.",
          },
        ],
        technologies: [],
        httpInfo: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/2",
          responseTimeMs: 80,
          contentLength: 5000,
          contentType: "text/html",
          isHttps: true,
          redirectChain: ["https://example.com/"],
          headers: {},
        },
        performanceMetrics: {
          ttfbMs: 120,
          totalPayloadKb: 5,
          compression: "gzip",
          cacheControl: "max-age=3600",
          scriptsCount: 1,
          stylesheetsCount: 1,
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
          headings: [{ level: 1, text: "Main Heading" }],
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
        browserExecution: {
          isSupported: true,
          executed: true,
          renderedDomByteLength: 8500,
          navigationDurationMs: 420,
          jsRenderedContentDetected: true,
          runtimeMixedContentCount: 1,
          observedResources: [
            {
              url: "http://insecure.test/script.js",
              resourceType: "script",
              isMixedContent: true,
              isHttps: false,
            },
          ],
        },
      };

      const md = generateIssuesMarkdown(mockResult);

      assert.match(md, /## Audit Scope & Limitations/);
      assert.match(md, /Isolated browser execution is unavailable/);
      assert.match(md, /## Browser Execution Diagnostics/);
      assert.match(md, /Rendered DOM Size\*\*: 8500 bytes/);
      assert.match(md, /Navigation Duration\*\*: 420 ms/);
      assert.match(md, /Dynamic JS Content Rendered\*\*: Yes/);
      assert.match(md, /Runtime Insecure Mixed Content\*\*: 1/);
    });
  });
});
