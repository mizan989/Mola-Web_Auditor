import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { ReconnaissanceMap } from "../types/audit.ts";
import { collectReconnaissance } from "../server/recon.ts";
import { runWebsiteAudit } from "../server/orchestrator.ts";
import { generateIssuesMarkdown } from "../lib/exportMarkdown.ts";

describe("Phase 3 — Reconnaissance Layer Verification", () => {
  const sampleHtml = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <title>Reconnaissance Target</title>
        <link rel="stylesheet" href="/css/app.css" />
        <script src="/js/app.js"></script>
        <script src="http://insecure.cdn.com/bad.js"></script>
      </head>
      <body>
        <main><h1>Recon Heading</h1></main>
        <img src="/img/banner.webp" alt="Banner" />
        <iframe src="https://embed.org/view" loading="lazy"></iframe>
      </body>
    </html>
  `;

  it("collects a deterministic surface map with complete metadata and provenance", () => {
    const recon: ReconnaissanceMap = collectReconnaissance({
      inputUrl: "http://example.com",
      normalizedUrl: "http://example.com/",
      finalUrl: "https://example.com/",
      redirectChain: ["http://example.com/", "https://example.com/"],
      validatedAddresses: ["93.184.216.34"],
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 55,
          contentLength: sampleHtml.length,
          contentType: "text/html; charset=utf-8",
          isHttps: true,
          redirectChain: ["http://example.com/", "https://example.com/"],
          headers: {
            "content-type": "text/html; charset=utf-8",
            "server": "cloudflare",
            "x-powered-by": "Next.js",
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
          "server": "cloudflare",
          "x-powered-by": "Next.js",
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
        },
        isTruncated: false,
      },
    });

    // 1. Target normalization & mapping
    assert.strictEqual(recon.target.inputUrl, "http://example.com");
    assert.strictEqual(recon.target.normalizedUrl, "http://example.com/");
    assert.strictEqual(recon.target.finalUrl, "https://example.com/");
    assert.strictEqual(recon.target.hostname, "example.com");
    assert.strictEqual(recon.target.scheme, "https");
    assert.strictEqual(recon.target.port, 443);
    assert.deepStrictEqual(recon.target.ipAddresses, ["93.184.216.34"]);

    // 2. Redirect chain
    assert.strictEqual(recon.redirectChain.length, 2);
    assert.strictEqual(recon.redirectChain[0].hopNumber, 1);
    assert.strictEqual(recon.redirectChain[0].url, "http://example.com/");
    assert.strictEqual(recon.redirectChain[1].hopNumber, 2);
    assert.strictEqual(recon.redirectChain[1].url, "https://example.com/");

    // 3. Status & timing
    assert.strictEqual(recon.status.code, 200);
    assert.strictEqual(recon.status.protocol, "HTTP/1.1 (TLS)");
    assert.strictEqual(recon.status.ttfbMs, 55);

    // 4. Bounded body metadata
    assert.strictEqual(recon.bodyMetadata.hasHtmlDoctype, true);
    assert.strictEqual(recon.bodyMetadata.charset, "utf-8");
    assert.strictEqual(recon.bodyMetadata.isTruncated, false);
    assert.strictEqual(recon.bodyMetadata.maxBodyLimitBytes, 2621440);

    // 5. Discovered resources
    assert.ok(recon.discoveredResources.scripts.includes("/js/app.js"));
    assert.ok(recon.discoveredResources.stylesheets.includes("/css/app.css"));
    assert.ok(recon.discoveredResources.images.includes("/img/banner.webp"));
    assert.ok(recon.discoveredResources.iframes.includes("https://embed.org/view"));

    // 6. Technology signals
    assert.ok(recon.technologySignals.some((t) => t.name === "Next.js"));

    // 7. Security observations with explicit provenance
    assert.ok(recon.securityObservations.length > 0);
    for (const obs of recon.securityObservations) {
      assert.ok(obs.type, "Observation must have a type");
      assert.ok(obs.observation, "Observation must have text");
      assert.ok(
        ["transport", "header", "redirect", "html"].includes(obs.provenance),
        `Invalid provenance: ${obs.provenance}`
      );
    }

    // Specific observation provenance checks
    assert.ok(recon.securityObservations.some((o) => o.provenance === "transport" && o.type === "tls-transport"));
    assert.ok(recon.securityObservations.some((o) => o.provenance === "redirect" && o.type === "http-to-https-upgrade"));
    assert.ok(recon.securityObservations.some((o) => o.provenance === "header" && o.type === "hsts-signal"));
    assert.ok(recon.securityObservations.some((o) => o.provenance === "header" && o.type === "server-disclosed"));
    assert.ok(recon.securityObservations.some((o) => o.provenance === "html" && o.type === "insecure-subresource-signal"));
  });

  it("ensures reconnaissance produces observations and signals, NOT findings", () => {
    const recon = collectReconnaissance({
      inputUrl: "http://example.com",
      normalizedUrl: "http://example.com/",
      finalUrl: "http://example.com/",
      redirectChain: ["http://example.com/"],
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1",
          responseTimeMs: 30,
          contentLength: 100,
          contentType: "text/html",
          isHttps: false,
          redirectChain: ["http://example.com/"],
          headers: {},
          isTruncated: false,
        },
        htmlText: "<html><head></head><body>Plaintext HTTP</body></html>",
        finalUrl: "http://example.com/",
        rawHeaders: {},
        isTruncated: false,
      },
    });

    // recon must be a structured surface map, not a findings array
    assert.ok(recon.securityObservations);
    assert.ok(Array.isArray(recon.securityObservations));
    // Verify observations are signals with provenance
    const plaintextObs = recon.securityObservations.find((o) => o.type === "plaintext-http");
    assert.ok(plaintextObs);
    assert.strictEqual(plaintextObs.provenance, "transport");
    assert.strictEqual(plaintextObs.severity, "warning");
    // Ensure it does not have finding properties like priority, recommendation, whyItMatters
    assert.strictEqual((plaintextObs as unknown as Record<string, unknown>).recommendation, undefined);
    assert.strictEqual((plaintextObs as unknown as Record<string, unknown>).whyItMatters, undefined);
    assert.strictEqual((plaintextObs as unknown as Record<string, unknown>).priority, undefined);
  });

  it("handles truncated response body limits safely in recon body metadata", () => {
    const recon = collectReconnaissance({
      inputUrl: "https://example.com/large",
      normalizedUrl: "https://example.com/large",
      finalUrl: "https://example.com/large",
      redirectChain: ["https://example.com/large"],
      httpResult: {
        info: {
          statusCode: 200,
          statusText: "OK",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 120,
          contentLength: 2621440,
          contentType: "text/html",
          isHttps: true,
          redirectChain: ["https://example.com/large"],
          headers: {},
          isTruncated: true,
        },
        htmlText: "<html><body>Truncated large document</body></html>",
        finalUrl: "https://example.com/large",
        rawHeaders: {},
        isTruncated: true,
      },
    });

    assert.strictEqual(recon.bodyMetadata.isTruncated, true);
    assert.ok(recon.limitations.length > 0);
    assert.match(recon.limitations[0], /2\.5 MB/);
  });

  it("handles failed connections safely with explicit failure limitations", () => {
    const recon = collectReconnaissance({
      inputUrl: "https://unreachable.example.org",
      normalizedUrl: "https://unreachable.example.org/",
      finalUrl: "https://unreachable.example.org/",
      redirectChain: ["https://unreachable.example.org/"],
      httpResult: {
        info: {
          statusCode: 0,
          statusText: "Connection Failed",
          protocol: "HTTP/1.1 (TLS)",
          responseTimeMs: 0,
          contentLength: 0,
          contentType: "unknown",
          isHttps: true,
          redirectChain: ["https://unreachable.example.org/"],
          headers: {},
          isTruncated: true,
        },
        htmlText: "",
        finalUrl: "https://unreachable.example.org/",
        rawHeaders: {},
        isTruncated: true,
      },
    });

    assert.strictEqual(recon.status.code, 0);
    assert.ok(recon.limitations.some((l) => l.includes("HTTP connection failed")));
  });

  it("integrates reconnaissance map into live runWebsiteAudit", async () => {
    const result = await runWebsiteAudit({ url: "https://example.com", mode: "quick" });

    assert.ok(result.reconnaissance, "Audit result must include reconnaissance surface map");
    assert.strictEqual(result.reconnaissance.target.hostname, "example.com");
    assert.strictEqual(result.reconnaissance.target.scheme, "https");
    assert.ok(result.reconnaissance.redirectChain.length >= 1);
    assert.ok(result.reconnaissance.status.code > 0);
    assert.ok(result.reconnaissance.securityObservations.length > 0);
  });

  it("formats reconnaissance surface map with provenance in exported markdown", () => {
    const mockScan = {
      scanId: "mola-recon-export",
      targetUrl: "https://example.com",
      finalUrl: "https://example.com/",
      hostname: "example.com",
      scanTimestamp: "2026-10-08T10:00:00Z",
      scanDurationMs: 80,
      scanMode: "quick" as const,
      status: "completed" as const,
      completeness: "full" as const,
      summary: {
        totalFindings: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        passedCount: 2,
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
        responseTimeMs: 40,
        contentLength: 1024,
        contentType: "text/html",
        isHttps: true,
        redirectChain: ["https://example.com/"],
        headers: {},
        isTruncated: false,
      },
      performanceMetrics: {
        ttfbMs: 40,
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
        headings: [],
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
      reconnaissance: {
        target: {
          inputUrl: "https://example.com",
          normalizedUrl: "https://example.com/",
          finalUrl: "https://example.com/",
          hostname: "example.com",
          scheme: "https" as const,
          port: 443,
          ipAddresses: ["93.184.216.34"],
        },
        redirectChain: [{ hopNumber: 1, url: "https://example.com/" }],
        status: {
          code: 200,
          text: "OK",
          protocol: "HTTP/1.1 (TLS)",
          ttfbMs: 40,
        },
        headers: {},
        bodyMetadata: {
          byteLength: 1024,
          characterLength: 1024,
          isTruncated: false,
          maxBodyLimitBytes: 2621440,
          contentType: "text/html",
          hasHtmlDoctype: true,
        },
        discoveredResources: {
          scripts: ["/app.js"],
          stylesheets: ["/style.css"],
          images: [],
          iframes: [],
        },
        technologySignals: [],
        securityObservations: [
          {
            type: "tls-transport",
            observation: "Encrypted HTTPS transport protocol active",
            provenance: "transport" as const,
            severity: "info" as const,
          },
        ],
        limitations: [],
        collectedAt: "2026-10-08T10:00:00Z",
      },
    };

    const md = generateIssuesMarkdown(mockScan);
    assert.match(md, /## Target Reconnaissance & Surface Map/);
    assert.match(md, /\*\*Host & Scheme\*\*:\s*`HTTPS` on `example\.com:443`/);
    assert.match(md, /\*\*Resolved Addresses\*\*:\s*`93\.184\.216\.34`/);
    assert.match(md, /\*\*Discovered Subresources\*\*:\s*Scripts: 1, Stylesheets: 1/);
    assert.match(md, /\[TRANSPORT\] Encrypted HTTPS transport protocol active/);
  });
});
