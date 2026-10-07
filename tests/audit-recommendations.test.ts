import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { auditSecurity } from "../server/scanners/security.ts";
import { auditPerformance } from "../server/scanners/performance.ts";
import { auditSeo } from "../server/scanners/seo.ts";

describe("Live Audit Recommendations Verification", () => {
  it("verifies HSTS is required for HTTPS and passes when header is present", () => {
    // Missing HSTS
    const missing = auditSecurity(
      {
        "content-type": "text/html",
      },
      "https://mola.antideploy.app",
      "<html><head></head><body></body></html>"
    );
    assert.ok(missing.findings.some((f) => f.id === "sec-hsts-missing"));

    // Enforced HSTS
    const present = auditSecurity(
      {
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy":
          "default-src 'self'; script-src 'self' 'nonce-test123' 'strict-dynamic'; object-src 'none';",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
      },
      "https://mola.antideploy.app",
      "<html><head></head><body></body></html>"
    );
    assert.strictEqual(
      present.findings.some((f) => f.id === "sec-hsts-missing"),
      false
    );
    assert.ok(present.passedChecks.some((p) => p.id === "sec-hsts-present"));
  });

  it("verifies CSP with nonce and strict-dynamic passes without flagging sec-csp-unsafe", () => {
    // Permissive CSP with unsafe-eval
    const unsafeEval = auditSecurity(
      {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline';",
      },
      "https://mola.antideploy.app",
      "<html><head></head><body></body></html>"
    );
    assert.ok(unsafeEval.findings.some((f) => f.id === "sec-csp-unsafe"));

    // Secure CSP with nonce and strict-dynamic
    const secureCsp = auditSecurity(
      {
        "content-type": "text/html",
        "content-security-policy":
          "default-src 'self'; script-src 'self' 'nonce-YTdkYjg4NjEtMTkxYy00ZGY5LTk2NDAtNTczNGI2NmVlMTZj' 'strict-dynamic'; style-src 'self' 'unsafe-inline';",
      },
      "https://mola.antideploy.app",
      "<html><head></head><body></body></html>"
    );
    assert.strictEqual(
      secureCsp.findings.some((f) => f.id === "sec-csp-unsafe"),
      false
    );
    assert.ok(secureCsp.passedChecks.some((p) => p.id === "sec-csp-present"));
  });

  it("ignores Next.js noModule fallback script and does not flag as render blocking", () => {
    const htmlWithNoModule = `
      <!DOCTYPE html>
      <html>
        <head>
          <script src="/_next/static/chunks/19mx3mg6lkumu.js" async=""></script>
          <script src="/_next/static/chunks/0cz1d0mv5g_q7.js" noModule=""></script>
        </head>
        <body>
          <main>Content</main>
        </body>
      </html>
    `;

    const perf = auditPerformance(
      120,
      15000,
      { "content-type": "text/html; charset=utf-8" },
      htmlWithNoModule
    );

    assert.strictEqual(
      perf.findings.some((f) => f.id === "perf-render-blocking-scripts"),
      false
    );
    assert.ok(perf.passedChecks.some((p) => p.id === "perf-scripts-deferred"));
  });

  it("detects canonical link tag in both attribute orders", () => {
    const html1 = `
      <!DOCTYPE html>
      <html>
        <head>
          <link rel="canonical" href="https://mola.antideploy.app" />
        </head>
        <body></body>
      </html>
    `;
    const seo1 = auditSeo(html1);
    assert.strictEqual(
      seo1.findings.some((f) => f.id === "seo-canonical-missing"),
      false
    );
    assert.ok(seo1.passedChecks.some((p) => p.id === "seo-canonical-present"));

    const html2 = `
      <!DOCTYPE html>
      <html>
        <head>
          <link href="https://mola.antideploy.app" rel="canonical" />
        </head>
        <body></body>
      </html>
    `;
    const seo2 = auditSeo(html2);
    assert.strictEqual(
      seo2.findings.some((f) => f.id === "seo-canonical-missing"),
      false
    );
    assert.ok(seo2.passedChecks.some((p) => p.id === "seo-canonical-present"));
  });

  it("flags x-powered-by when disclosed and passes when disabled", () => {
    const disclosed = auditSecurity(
      {
        "content-type": "text/html",
        "x-powered-by": "Next.js",
      },
      "https://mola.antideploy.app",
      "<html><head></head><body></body></html>"
    );
    assert.ok(disclosed.findings.some((f) => f.id === "sec-powered-by-leak"));

    const disabled = auditSecurity(
      {
        "content-type": "text/html",
      },
      "https://mola.antideploy.app",
      "<html><head></head><body></body></html>"
    );
    assert.strictEqual(
      disabled.findings.some((f) => f.id === "sec-powered-by-leak"),
      false
    );
  });
});
