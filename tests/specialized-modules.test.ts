import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  auditHttpInfrastructure,
  auditSecurityHeaders,
  auditCookies,
  auditTls,
  auditMixedContent,
  auditSeo,
  auditAccessibility,
  auditBestPractices,
  detectTechnologies,
  auditResourceIntegrity,
  auditIframeSafety,
  runAllAuditModules,
} from "../server/modules/index.ts";
import { auditSecurity } from "../server/scanners/security.ts";
import { auditDeepScan } from "../server/scanners/deep.ts";
import { auditPerformance } from "../server/scanners/performance.ts";
import { buildAuditContext } from "../server/context.ts";
import type { AuditContext } from "../types/audit.ts";

describe("Phase 8 — Specialized Audit Modules", () => {
  const dummyContext: AuditContext = {
    targetUrl: "https://example.com",
    finalUrl: "https://example.com",
    hostname: "example.com",
    scanMode: "quick",
    redirectChain: ["https://example.com"],
    headers: {
      "content-type": "text/html",
      "content-encoding": "gzip",
      "cache-control": "public, max-age=3600",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()",
    },
    body: {
      text: `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Valid Title Exceeding Thirty Characters</title><meta name="description" content="A valid meta description text exceeding seventy characters for search engine crawlers."><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="canonical" href="https://example.com"><meta property="og:title" content="Valid OG Title"><meta property="og:image" content="https://example.com/og.png"></head><body><h1>Main Heading</h1><main><p>Content</p></main></body></html>`,
      byteLength: 550,
      isTruncated: false,
    },
    timing: { startTime: 1000, ttfbMs: 150 },
    response: {
      statusCode: 200,
      statusText: "OK",
      protocol: "HTTP/1.1",
      isHttps: true,
      responseTimeMs: 150,
      contentLength: 450,
      contentType: "text/html",
    },
    discoveredResources: { scripts: [], stylesheets: [], images: [], iframes: [] },
    technologyObservations: [],
    limitations: [],
    metadata: {
      scanId: "test-scan",
      userAgent: "MolaWebAuditor/1.0",
      timestamp: new Date().toISOString(),
      isPartial: false,
    },
  };

  describe("1. HTTP & Infrastructure Module", () => {
    it("evaluates fast TTFB, compression, and caching on healthy responses", () => {
      const res = auditHttpInfrastructure(dummyContext);
      assert.ok(res.passedChecks.some((c) => c.id === "perf-ttfb-fast"));
      assert.ok(res.passedChecks.some((c) => c.id === "perf-compression-enabled"));
      assert.ok(res.passedChecks.some((c) => c.id === "perf-cache-control-present"));
      assert.equal(res.findings.length, 0);
    });

    it("evaluates high TTFB latency, missing compression, and missing cache-control", () => {
      const res = auditHttpInfrastructure({
        responseTimeMs: 1500,
        contentLength: 50000,
        headers: {},
        isTruncated: false,
      });
      assert.ok(res.findings.some((f) => f.id === "perf-high-ttfb"));
      assert.ok(res.findings.some((f) => f.id === "perf-compression-missing"));
      assert.ok(res.findings.some((f) => f.id === "perf-cache-control-missing"));
    });

    it("detects body payload truncation cleanly", () => {
      const res = auditHttpInfrastructure({
        responseTimeMs: 200,
        contentLength: 2600000,
        headers: { "content-encoding": "br", "cache-control": "no-cache" },
        isTruncated: true,
        finalUrl: "https://large.example.com",
      });
      assert.ok(res.findings.some((f) => f.id === "perf-payload-truncated"));
    });

    it("handles connection/reachability failures as unable_to_check findings", () => {
      const res = auditHttpInfrastructure({
        statusCode: 0,
        isPartial: true,
        failureReason: "ECONNRESET",
        finalUrl: "https://offline.example.com",
      });
      const connFinding = res.findings.find((f) => f.id === "sec-connection-failed");
      assert.ok(connFinding);
      assert.equal(connFinding.state, "unable_to_check");
      assert.equal(connFinding.severity, "high");
    });
  });

  describe("2. Security Headers Module", () => {
    it("flags missing CSP, HSTS, XFO, XCTO, Referrer-Policy, and Permissions-Policy", () => {
      const res = auditSecurityHeaders({}, "https://example.com");
      assert.ok(res.findings.some((f) => f.id === "sec-csp-missing"));
      assert.ok(res.findings.some((f) => f.id === "sec-hsts-missing"));
      assert.ok(res.findings.some((f) => f.id === "sec-xfo-missing"));
      assert.ok(res.findings.some((f) => f.id === "sec-xcto-missing"));
      assert.ok(res.findings.some((f) => f.id === "sec-ref-policy-missing"));
      assert.ok(res.findings.some((f) => f.id === "sec-perm-policy-missing"));
    });

    it("flags unsafe CSP eval/inline and server/powered-by version leaks", () => {
      const res = auditSecurityHeaders(
        {
          "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'",
          server: "Apache/2.4.41 (Ubuntu)",
          "x-powered-by": "Express",
        },
        "https://example.com"
      );
      assert.ok(res.findings.some((f) => f.id === "sec-csp-unsafe"));
      assert.ok(res.findings.some((f) => f.id === "sec-server-version-leak"));
      assert.ok(res.findings.some((f) => f.id === "sec-powered-by-leak"));
    });

    it("verifies clean security headers produce passed checks", () => {
      const res = auditSecurityHeaders(dummyContext);
      assert.ok(res.passedChecks.some((c) => c.id === "sec-csp-present"));
      assert.ok(res.passedChecks.some((c) => c.id === "sec-hsts-present"));
      assert.ok(res.passedChecks.some((c) => c.id === "sec-xfo-present"));
      assert.ok(res.passedChecks.some((c) => c.id === "sec-xcto-present"));
      assert.ok(res.passedChecks.some((c) => c.id === "sec-ref-policy-present"));
      assert.ok(res.passedChecks.some((c) => c.id === "sec-perm-policy-present"));
    });
  });

  describe("3. Cookies Module", () => {
    it("flags insecure cookies lacking Secure, HttpOnly, or SameSite", () => {
      const res = auditCookies({ "set-cookie": "session_id=12345; Path=/" }, "https://example.com");
      const cookieFinding = res.findings.find((f) => f.id === "sec-cookie-insecure");
      assert.ok(cookieFinding);
      assert.equal(cookieFinding.severity, "medium");
      assert.equal(cookieFinding.state, "confirmed");
    });

    it("verifies hardened cookies with all security flags", () => {
      const res = auditCookies(
        { "set-cookie": "session_id=12345; Path=/; Secure; HttpOnly; SameSite=Strict" },
        "https://example.com"
      );
      assert.ok(res.passedChecks.some((c) => c.id === "sec-cookie-hardened"));
      assert.equal(res.findings.length, 0);
    });
  });

  describe("4. TLS Observations Module", () => {
    it("flags unencrypted plaintext HTTP transport", () => {
      const res = auditTls("http://insecure.example.com");
      assert.ok(res.findings.some((f) => f.id === "sec-insecure-http"));
    });

    it("confirms encrypted HTTPS transport", () => {
      const res = auditTls("https://secure.example.com");
      assert.ok(res.passedChecks.some((c) => c.id === "sec-https-enforced"));
    });
  });

  describe("5. Mixed Content Module", () => {
    it("detects insecure HTTP subresources loaded on HTTPS pages", () => {
      const html = `<html><head><script src="http://cdn.example.com/app.js"></script></head><body><img src="http://example.com/logo.png"></body></html>`;
      const res = auditMixedContent({ isHttps: true, finalUrl: "https://example.com", htmlText: html });
      const mixed = res.findings.find((f) => f.id === "sec-mixed-content");
      assert.ok(mixed);
      assert.equal(mixed.severity, "high");
      assert.equal(mixed.priority, "critical");
    });

    it("confirms zero mixed content on clean HTTPS pages", () => {
      const html = `<html><head><script src="https://cdn.example.com/app.js"></script></head><body><img src="/logo.png"></body></html>`;
      const res = auditMixedContent({ isHttps: true, finalUrl: "https://example.com", htmlText: html });
      assert.ok(res.passedChecks.some((c) => c.id === "sec-mixed-content-clean"));
    });
  });

  describe("6. SEO Module", () => {
    it("inspects titles, metas, canonical links, and headings", () => {
      const res = auditSeo(dummyContext);
      assert.equal(res.findings.length, 0);
      assert.equal(res.seoData.title, "Valid Title Exceeding Thirty Characters");
      assert.ok(res.seoData.titleLength > 30);
      assert.ok(res.seoData.metaDescription);
      assert.equal(res.seoData.h1Count, 1);
    });

    it("flags missing title and short meta description", () => {
      const res = auditSeo("<html><head><meta name='description' content='short'></head><body></body></html>");
      assert.ok(res.findings.some((f) => f.id === "seo-title-missing"));
      assert.ok(res.findings.some((f) => f.id === "seo-meta-description-short"));
    });
  });

  describe("7. Accessibility Module", () => {
    it("inspects document language, image alternatives, and form inputs", () => {
      const res = auditAccessibility(dummyContext);
      assert.equal(res.findings.length, 0);
      assert.equal(res.summary.hasLang, true);
      assert.equal(res.summary.imagesMissingAlt, 0);
      assert.equal(res.summary.inputsMissingLabel, 0);
      assert.equal(res.summary.hasMainLandmark, true);
    });

    it("flags missing html lang and unlabelled inputs", () => {
      const res = auditAccessibility("<html><body><input type='text'><img src='pic.jpg'></body></html>");
      assert.ok(res.findings.some((f) => f.id === "a11y-html-lang-missing"));
      assert.ok(res.findings.some((f) => f.id === "a11y-inputs-unlabelled"));
      assert.ok(res.findings.some((f) => f.id === "a11y-images-missing-alt"));
    });
  });

  describe("8. Best Practices Module", () => {
    it("inspects HTML5 doctype and charset encoding", () => {
      const res = auditBestPractices(dummyContext);
      assert.ok(res.passedChecks.some((c) => c.id === "bp-doctype-present"));
      assert.ok(res.passedChecks.some((c) => c.id === "bp-charset-present"));
    });
  });

  describe("9. Technology Detection Module", () => {
    it("detects Next.js and React technologies from authentic markers", () => {
      const html = `<div id="__next">Hello world</div><script src="/_next/static/chunks/main.js"></script>`;
      const techs = detectTechnologies({ headers: { "x-powered-by": "Next.js" }, body: { text: html } } as unknown as AuditContext);
      assert.ok(techs.some((t) => t.name === "Next.js"));
      assert.ok(techs.some((t) => t.name === "React"));
    });
  });

  describe("10. Resource Integrity Module", () => {
    it("flags third-party scripts lacking cryptographic SRI attributes", () => {
      const html = `<html><head><script src="https://cdn.thirdparty.com/lib.js"></script></head><body></body></html>`;
      const res = auditResourceIntegrity({ finalUrl: "https://my-app.com", htmlText: html });
      assert.ok(res.findings.some((f) => f.id === "sec-sri-missing"));
    });

    it("verifies external scripts equipped with integrity hashes", () => {
      const html = `<html><head><script src="https://cdn.thirdparty.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script></head><body></body></html>`;
      const res = auditResourceIntegrity({ finalUrl: "https://my-app.com", htmlText: html });
      assert.ok(res.passedChecks.some((c) => c.id === "sec-sri-verified"));
    });
  });

  describe("11. Iframe Safety Module", () => {
    it("flags iframes lacking sandbox and loading='lazy'", () => {
      const html = `<html><body><iframe src="https://embed.com/widget"></iframe></body></html>`;
      const res = auditIframeSafety({ finalUrl: "https://my-app.com", htmlText: html });
      assert.ok(res.findings.some((f) => f.id === "sec-iframe-sandbox-missing"));
      assert.ok(res.findings.some((f) => f.id === "perf-iframe-lazy-missing"));
    });
  });

  describe("12. Unified runAllAuditModules & Scanner Compositions", () => {
    it("executes unified module runner across all modules in Quick mode", () => {
      const res = runAllAuditModules(dummyContext, { mode: "quick" });
      assert.ok(res.findings);
      assert.ok(res.passedChecks);
      assert.ok(res.seoData);
      assert.ok(res.a11ySummary);
      assert.ok(res.performanceMetrics);
    });

    it("executes unified module runner across all modules in Deep mode", () => {
      const deepCtx: AuditContext = {
        ...dummyContext,
        scanMode: "deep",
        body: {
          text: `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><script src="https://cdn.thirdparty.com/lib.js"></script></head><body><iframe src="https://embed.com"></iframe></body></html>`,
          byteLength: 200,
          isTruncated: false,
        },
      };

      const res = runAllAuditModules(deepCtx, { mode: "deep" });
      assert.ok(res.findings.some((f) => f.id === "sec-sri-missing"));
      assert.ok(res.findings.some((f) => f.id === "sec-iframe-sandbox-missing"));
    });

    it("preserves backward-compatible composite scanner behavior", () => {
      const sec = auditSecurity(dummyContext);
      assert.ok(sec.passedChecks.some((c) => c.id === "sec-https-enforced"));
      assert.ok(sec.passedChecks.some((c) => c.id === "sec-csp-present"));

      const deep = auditDeepScan(dummyContext);
      assert.ok(deep.findings !== undefined);

      const perf = auditPerformance(dummyContext);
      assert.ok(perf.metrics);
      assert.ok(perf.passedChecks.some((c) => c.id === "perf-ttfb-fast"));
    });
  });
});
