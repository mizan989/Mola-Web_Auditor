import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AuditContext } from "../types/audit.ts";
import {
  buildAuditContext,
  createPartialAuditContext,
  extractDiscoveredResources,
  isAuditContext,
} from "../server/context.ts";
import { auditSecurity } from "../server/scanners/security.ts";
import { auditPerformance } from "../server/scanners/performance.ts";
import { auditSeo } from "../server/scanners/seo.ts";
import { auditAccessibility } from "../server/scanners/a11y.ts";
import { auditBestPractices } from "../server/scanners/bestPractices.ts";
import { detectTechnologies } from "../server/scanners/tech.ts";
import { auditDeepScan } from "../server/scanners/deep.ts";
import { runWebsiteAudit } from "../server/orchestrator.ts";

describe("Phase 2 — Shared Audit Context Verification", () => {
  const sampleHtml = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Test Page</title>
        <link rel="stylesheet" href="/styles/main.css" />
        <link href="https://cdn.example.com/vendor.css" rel="stylesheet" />
        <script src="/scripts/bundle.js"></script>
        <script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>
      </head>
      <body>
        <h1>Heading 1</h1>
        <img src="/img/logo.png" alt="Company Logo" />
        <img src="/img/hero.jpg" />
        <iframe src="https://embed.example.com/widget" sandbox="allow-scripts" loading="lazy"></iframe>
      </body>
    </html>
  `;

  it("extracts discovered subresources deterministically from HTML text", () => {
    const res = extractDiscoveredResources(sampleHtml);
    assert.deepStrictEqual(res.scripts, ["/scripts/bundle.js", "https://cdn.example.com/lib.js"]);
    assert.deepStrictEqual(res.stylesheets, ["/styles/main.css", "https://cdn.example.com/vendor.css"]);
    assert.deepStrictEqual(res.images, ["/img/logo.png", "/img/hero.jpg"]);
    assert.deepStrictEqual(res.iframes, ["https://embed.example.com/widget"]);
  });

  it("builds a complete, authoritative AuditContext with all required data layers", () => {
    const startTime = Date.now() - 250;
    const context = buildAuditContext({
      targetUrl: "https://example.com/",
      finalUrl: "https://example.com/",
      scanMode: "quick",
      scanId: "test-scan-context-1",
      startTime,
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 65,
          contentLength: sampleHtml.length,
          contentType: "text/html; charset=utf-8",
          isHttps: true,
          redirectChain: ["https://example.com/"],
          headers: {
            "content-type": "text/html; charset=utf-8",
            "x-powered-by": "Next.js",
            "strict-transport-security": "max-age=31536000",
          },
          isTruncated: false,
        },
        htmlText: sampleHtml,
        finalUrl: "https://example.com/",
        rawHeaders: {
          "content-type": "text/html; charset=utf-8",
          "x-powered-by": "Next.js",
          "strict-transport-security": "max-age=31536000",
        },
        isTruncated: false,
      },
    });

    assert.ok(isAuditContext(context));
    assert.strictEqual(context.targetUrl, "https://example.com/");
    assert.strictEqual(context.finalUrl, "https://example.com/");
    assert.strictEqual(context.hostname, "example.com");
    assert.strictEqual(context.scanMode, "quick");
    assert.strictEqual(context.response.statusCode, 200);
    assert.strictEqual(context.response.isHttps, true);
    assert.strictEqual(context.body.isTruncated, false);
    assert.strictEqual(context.timing.ttfbMs, 65);
    assert.ok(context.discoveredResources.scripts.length > 0);
    assert.ok(context.discoveredResources.stylesheets.length > 0);
    assert.ok(context.technologyObservations.some((t) => t.name === "Next.js"));
    assert.strictEqual(context.metadata.scanId, "test-scan-context-1");
  });

  it("handles validated redirect chains correctly without trusting unvalidated hops", () => {
    const startTime = Date.now() - 300;
    const validatedChain = ["http://example.com/", "https://example.com/"];

    const context = buildAuditContext({
      targetUrl: "http://example.com/",
      finalUrl: "https://example.com/",
      scanMode: "quick",
      scanId: "test-scan-redirect",
      startTime,
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 90,
          contentLength: 1024,
          contentType: "text/html",
          isHttps: true,
          redirectChain: validatedChain,
          headers: {},
          isTruncated: false,
        },
        htmlText: "<html><head><title>Redirected</title></head><body></body></html>",
        finalUrl: "https://example.com/",
        rawHeaders: {},
        isTruncated: false,
      },
    });

    assert.strictEqual(context.targetUrl, "http://example.com/");
    assert.strictEqual(context.finalUrl, "https://example.com/");
    assert.deepStrictEqual(context.redirectChain, validatedChain);
    // Final destination is HTTPS even though initial target was HTTP
    assert.strictEqual(context.response.isHttps, true);
  });

  it("records explicit limitations and partial status for truncated document payloads", () => {
    const startTime = Date.now() - 200;
    const context = buildAuditContext({
      targetUrl: "https://example.com/large",
      finalUrl: "https://example.com/large",
      scanMode: "quick",
      scanId: "test-scan-truncated",
      startTime,
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 150,
          contentLength: 2621440,
          contentType: "text/html",
          isHttps: true,
          redirectChain: ["https://example.com/large"],
          headers: {},
          isTruncated: true,
        },
        htmlText: "<html><head></head><body>Large payload truncated</body></html>",
        finalUrl: "https://example.com/large",
        rawHeaders: {},
        isTruncated: true,
      },
    });

    assert.strictEqual(context.body.isTruncated, true);
    assert.strictEqual(context.metadata.isPartial, true);
    assert.ok(context.limitations.length > 0);
    assert.match(context.limitations[0], /2\.5 MB/);
  });

  it("creates a safe partial AuditContext on failed connection without throwing", () => {
    const startTime = Date.now() - 100;
    const partialCtx = createPartialAuditContext({
      targetUrl: "https://failed.example.org/",
      scanMode: "quick",
      scanId: "test-scan-failed",
      startTime,
      failureReason: "ECONNREFUSED: Connection refused by target",
      partialHeaders: {},
      partialHtml: "",
    });

    assert.ok(isAuditContext(partialCtx));
    assert.strictEqual(partialCtx.response.statusCode, 0);
    assert.strictEqual(partialCtx.metadata.isPartial, true);
    assert.strictEqual(partialCtx.metadata.failureReason, "ECONNREFUSED: Connection refused by target");
    assert.ok(partialCtx.limitations.some((l) => l.includes("ECONNREFUSED")));

    // When security scanner runs against failed context, it outputs unable_to_check finding safely
    const secResult = auditSecurity(partialCtx);
    assert.ok(secResult.findings.length > 0);
    const failedFinding = secResult.findings.find((f) => f.id === "sec-connection-failed");
    assert.ok(failedFinding);
    assert.strictEqual(failedFinding.state, "unable_to_check");
    assert.strictEqual(failedFinding.confidence, "high");

    // Other scanners handle partial context safely without crashing
    const perfResult = auditPerformance(partialCtx);
    assert.strictEqual(perfResult.metrics.ttfbMs, 0);

    const seoResult = auditSeo(partialCtx);
    assert.strictEqual(seoResult.seoData.title, null);

    const a11yResult = auditAccessibility(partialCtx);
    assert.strictEqual(a11yResult.summary.imagesTotal, 0);

    const bpResult = auditBestPractices(partialCtx);
    assert.ok(bpResult.findings.some((f) => f.id === "bp-doctype-missing"));
  });

  it("verifies all core scanners directly consume AuditContext as an authoritative source", () => {
    const context: AuditContext = buildAuditContext({
      targetUrl: "https://example.com/",
      finalUrl: "https://example.com/",
      scanMode: "deep",
      scanId: "test-scan-direct-consumer",
      startTime: Date.now() - 150,
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 40,
          contentLength: sampleHtml.length,
          contentType: "text/html; charset=utf-8",
          isHttps: true,
          redirectChain: ["https://example.com/"],
          headers: {
            "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
          },
          isTruncated: false,
        },
        htmlText: sampleHtml,
        finalUrl: "https://example.com/",
        rawHeaders: {
          "content-type": "text/html; charset=utf-8",
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
        },
        isTruncated: false,
      },
    });

    // 1. Security scanner
    const secResult = auditSecurity(context);
    assert.ok(secResult.passedChecks.some((p) => p.id === "sec-hsts-present"));

    // 2. Performance scanner
    const perfResult = auditPerformance(context);
    assert.strictEqual(perfResult.metrics.ttfbMs, 40);

    // 3. SEO scanner
    const seoResult = auditSeo(context);
    assert.strictEqual(seoResult.seoData.title, "Test Page");

    // 4. Accessibility scanner
    const a11yResult = auditAccessibility(context);
    assert.strictEqual(a11yResult.summary.hasLang, true);

    // 5. Best practices scanner
    const bpResult = auditBestPractices(context);
    assert.ok(bpResult.passedChecks.some((p) => p.id === "bp-doctype-present"));

    // 6. Technology detection
    const techs = detectTechnologies(context);
    assert.ok(Array.isArray(techs));

    // 7. Deep scan
    const deepResult = auditDeepScan(context);
    assert.ok(deepResult.passedChecks.length > 0 || deepResult.findings.length > 0);
  });

  it("verifies live runWebsiteAudit orchestrates via shared AuditContext", async () => {
    const result = await runWebsiteAudit({ url: "https://example.com", mode: "quick" });
    assert.ok(result.scanId.startsWith("mola-"));
    assert.strictEqual(result.hostname, "example.com");
    assert.ok(result.summary.totalFindings >= 0);
    assert.ok(result.summary.passedCount > 0);
  });
});
