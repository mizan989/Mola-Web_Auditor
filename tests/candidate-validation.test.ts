import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  validateHstsCandidate,
  validateCspUnsafeCandidate,
  validateXfoCandidate,
  validateCookieCandidate,
  validateMixedContentCandidate,
  validateTechnologyCandidate,
  validateSriCandidate,
  validateIframeSecurityCandidate,
  validateInputLabelCandidate,
  validateImageAltCandidate,
  validateCanonicalCandidate,
} from "../server/candidateValidator.ts";
import { auditSecurity } from "../server/scanners/security.ts";
import { auditDeepScan } from "../server/scanners/deep.ts";
import { detectTechnologies } from "../server/scanners/tech.ts";
import { auditSeo } from "../server/scanners/seo.ts";
import { auditAccessibility } from "../server/scanners/a11y.ts";

describe("Phase 5 — Candidate Detection vs Evidence Validation", () => {
  // ==========================================
  // Domain 1: Security Headers
  // ==========================================
  describe("1. Security Headers Candidate Validation", () => {
    it("rejects HSTS missing candidate for plain HTTP targets (RFC 6797 §7.2)", () => {
      const evalResult = validateHstsCandidate({ isHttps: false });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /invalid over plain HTTP/i);
    });

    it("confirms HSTS missing candidate for HTTPS targets without HSTS header", () => {
      const evalResult = validateHstsCandidate({ isHttps: true });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "sec-hsts-missing");
    });

    it("confirms HSTS disabled candidate when max-age=0 is declared", () => {
      const evalResult = validateHstsCandidate({
        isHttps: true,
        hstsHeader: "max-age=0; includeSubDomains",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "sec-hsts-disabled");
    });

    it("rejects HSTS candidate when valid max-age is declared", () => {
      const evalResult = validateHstsCandidate({
        isHttps: true,
        hstsHeader: "max-age=31536000; includeSubDomains; preload",
      });
      assert.equal(evalResult.outcome, "rejected");
    });

    it("rejects CSP unsafe candidate when 'unsafe-inline' is neutralized by nonce or strict-dynamic (CSP Level 3)", () => {
      // Nonce neutralization
      const nonceEval = validateCspUnsafeCandidate({
        cspHeader: "script-src 'self' 'unsafe-inline' 'nonce-rAnd0m12345'",
      });
      assert.equal(nonceEval.outcome, "rejected");
      assert.match(nonceEval.reason, /CSP Level 3 defense.*neutralized/i);

      // strict-dynamic neutralization
      const strictEval = validateCspUnsafeCandidate({
        cspHeader: "script-src 'self' 'unsafe-inline' 'strict-dynamic'",
      });
      assert.equal(strictEval.outcome, "rejected");

      // Hash neutralization
      const hashEval = validateCspUnsafeCandidate({
        cspHeader: "script-src 'self' 'unsafe-inline' 'sha256-abcdef1234567890'",
      });
      assert.equal(hashEval.outcome, "rejected");
    });

    it("confirms CSP unsafe candidate when un-nonced 'unsafe-inline' is used", () => {
      const evalResult = validateCspUnsafeCandidate({
        cspHeader: "script-src 'self' 'unsafe-inline'",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "sec-csp-unsafe");
    });

    it("confirms CSP unsafe candidate when 'unsafe-eval' is used", () => {
      const evalResult = validateCspUnsafeCandidate({
        cspHeader: "script-src 'self' 'unsafe-eval' 'nonce-12345'",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.match(evalResult.reason, /unsafe-eval/i);
    });

    it("rejects X-Frame-Options missing candidate when CSP frame-ancestors is present", () => {
      const evalResult = validateXfoCandidate({
        cspHeader: "default-src 'self'; frame-ancestors 'none'",
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /frame-ancestors.*supersedes/i);
    });

    it("confirms X-Frame-Options missing candidate when neither XFO nor frame-ancestors exist", () => {
      const evalResult = validateXfoCandidate({
        cspHeader: "default-src 'self'",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "sec-xfo-missing");
    });

    it("scanner integration: rejected candidates NEVER appear in auditSecurity findings", () => {
      // HTTPS target with CSP Level 3 nonce and frame-ancestors
      const headers = {
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc123'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
      };
      const finalUrl = "https://example.com";
      const htmlText = "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>";

      const secResult = auditSecurity(headers, finalUrl, htmlText);

      const cspUnsafe = secResult.findings.find((f) => f.id === "sec-csp-unsafe");
      const xfoMissing = secResult.findings.find((f) => f.id === "sec-xfo-missing");
      const hstsMissing = secResult.findings.find((f) => f.id === "sec-hsts-missing");

      assert.equal(cspUnsafe, undefined, "Rejected sec-csp-unsafe must not become a finding");
      assert.equal(xfoMissing, undefined, "Rejected sec-xfo-missing must not become a finding");
      assert.equal(hstsMissing, undefined, "Rejected sec-hsts-missing must not become a finding");
    });
  });

  // ==========================================
  // Domain 2: Cookies
  // ==========================================
  describe("2. Cookie Candidate Validation", () => {
    it("rejects Secure flag requirement when cookie is served over plain HTTP", () => {
      const evalResult = validateCookieCandidate({
        cookieString: "sessionId=12345; HttpOnly; SameSite=Strict",
        isHttps: false,
      });
      // Not HTTPS, so missing Secure is NOT flagged as an issue
      assert.equal(evalResult.outcome, "rejected");
    });

    it("confirms insecure cookie candidate when missing Secure on HTTPS", () => {
      const evalResult = validateCookieCandidate({
        cookieString: "sessionId=12345; HttpOnly; SameSite=Strict",
        isHttps: true,
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.ok(evalResult.candidateValue?.issues.includes("missing 'Secure' flag"));
    });

    it("confirms insecure cookie candidate when missing HttpOnly", () => {
      const evalResult = validateCookieCandidate({
        cookieString: "token=xyz; Secure; SameSite=Lax",
        isHttps: true,
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.ok(evalResult.candidateValue?.issues.includes("missing 'HttpOnly' flag"));
    });

    it("confirms insecure cookie candidate when missing SameSite", () => {
      const evalResult = validateCookieCandidate({
        cookieString: "token=xyz; Secure; HttpOnly",
        isHttps: true,
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.ok(evalResult.candidateValue?.issues.includes("missing 'SameSite' attribute"));
    });

    it("rejects candidate when cookie is fully hardened with Secure, HttpOnly, and SameSite", () => {
      const evalResult = validateCookieCandidate({
        cookieString: "token=xyz; Secure; HttpOnly; SameSite=Strict; Path=/",
        isHttps: true,
      });
      assert.equal(evalResult.outcome, "rejected");
    });
  });

  // ==========================================
  // Domain 3: Mixed Content
  // ==========================================
  describe("3. Mixed Content Candidate Validation", () => {
    it("rejects candidate when base site is plain HTTP (mixed content only applies to HTTPS)", () => {
      const evalResult = validateMixedContentCandidate({
        url: "http://example.com/asset.js",
        isHttps: false,
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /plain HTTP/i);
    });

    it("rejects candidate when URL is a non-fetched XML namespace or metadata schema URI", () => {
      const w3cEval = validateMixedContentCandidate({
        url: "http://www.w3.org/1999/xhtml",
        isHttps: true,
      });
      assert.equal(w3cEval.outcome, "rejected");
      assert.match(w3cEval.reason, /XML namespace/i);

      const schemaEval = validateMixedContentCandidate({
        url: "http://schema.org/WebPage",
        isHttps: true,
      });
      assert.equal(schemaEval.outcome, "rejected");
    });

    it("confirms candidate when an active insecure subresource is requested on HTTPS", () => {
      const evalResult = validateMixedContentCandidate({
        url: "http://cdn.example.com/script.js",
        isHttps: true,
        tag: "script",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "sec-mixed-content");
    });
  });

  // ==========================================
  // Domain 4: Technology Detection
  // ==========================================
  describe("4. Technology Detection Candidate Validation", () => {
    it("rejects React candidate when word 'reaction' or 'reacting' appears without authentic bundle/root", () => {
      const evalResult = validateTechnologyCandidate({
        techName: "React",
        rawSignal: "reaction",
        hasDirectProof: false,
        hasClusterProof: false,
        evidence: "",
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /lacks DOM\/bundle proof/i);
    });

    it("confirms React candidate when data-reactroot or React script bundle exists", () => {
      const evalResult = validateTechnologyCandidate({
        techName: "React",
        rawSignal: "react",
        hasDirectProof: true,
        hasClusterProof: false,
        evidence: "DOM attribute: data-reactroot",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.candidateValue, "React");
    });

    it("rejects Tailwind CSS candidate on isolated utility classes without stylesheet/cluster", () => {
      const evalResult = validateTechnologyCandidate({
        techName: "Tailwind CSS",
        rawSignal: "tailwind",
        hasDirectProof: false,
        hasClusterProof: false,
        evidence: "",
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /Isolated utility class/i);
    });

    it("confirms Tailwind CSS candidate on dedicated stylesheet or high-confidence class cluster", () => {
      const evalResult = validateTechnologyCandidate({
        techName: "Tailwind CSS",
        rawSignal: "tailwind",
        hasDirectProof: false,
        hasClusterProof: true,
        evidence: "Detected 4 prefixed utility classes and 2 arbitrary directives",
      });
      assert.equal(evalResult.outcome, "confirmed");
    });

    it("scanner integration: detectTechnologies never yields false-positive React or Tailwind", () => {
      const html = `
        <!DOCTYPE html>
        <html>
          <body>
            <p class="flex">Chemical reaction experiment</p>
          </body>
        </html>
      `;
      const techs = detectTechnologies({}, html);
      assert.equal(techs.find((t) => t.name === "React"), undefined);
      assert.equal(techs.find((t) => t.name === "Tailwind CSS"), undefined);
    });
  });

  // ==========================================
  // Domain 5: Subresource Integrity (SRI)
  // ==========================================
  describe("5. Subresource Integrity (SRI) Candidate Validation", () => {
    it("rejects SRI candidate for relative first-party script paths", () => {
      const evalResult = validateSriCandidate({
        src: "/assets/app.js",
        host: "example.com",
        finalUrl: "https://example.com/",
        hasIntegrity: false,
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /First-party relative script path/i);
    });

    it("rejects SRI candidate for same-origin absolute scripts", () => {
      const evalResult = validateSriCandidate({
        src: "https://example.com/assets/app.js",
        host: "example.com",
        finalUrl: "https://example.com/",
        hasIntegrity: false,
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /First-party script hosted on target origin/i);
    });

    it("rejects SRI candidate for external scripts declaring cryptographic integrity attribute", () => {
      const evalResult = validateSriCandidate({
        src: "https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js",
        host: "example.com",
        finalUrl: "https://example.com/",
        hasIntegrity: true,
      });
      assert.equal(evalResult.outcome, "rejected");
      assert.match(evalResult.reason, /valid cryptographic integrity/i);
    });

    it("confirms SRI missing candidate for external third-party CDN scripts without integrity", () => {
      const evalResult = validateSriCandidate({
        src: "https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js",
        host: "example.com",
        finalUrl: "https://example.com/",
        hasIntegrity: false,
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "sec-sri-missing");
    });
  });

  // ==========================================
  // Domain 6: Iframe Security
  // ==========================================
  describe("6. Iframe Security Candidate Validation", () => {
    it("rejects sandbox defect candidate when iframe declares sandbox attribute", () => {
      const { sandboxEvaluation, lazyEvaluation } = validateIframeSecurityCandidate({
        src: "https://maps.google.com/embed",
        hasSandbox: true,
        isLazy: false,
      });
      assert.equal(sandboxEvaluation.outcome, "rejected");
      assert.equal(lazyEvaluation.outcome, "confirmed");
    });

    it("rejects lazy loading candidate when iframe declares loading='lazy'", () => {
      const { sandboxEvaluation, lazyEvaluation } = validateIframeSecurityCandidate({
        src: "https://maps.google.com/embed",
        hasSandbox: false,
        isLazy: true,
      });
      assert.equal(sandboxEvaluation.outcome, "confirmed");
      assert.equal(lazyEvaluation.outcome, "rejected");
    });

    it("rejects both candidates when iframe is fully hardened", () => {
      const { sandboxEvaluation, lazyEvaluation } = validateIframeSecurityCandidate({
        src: "https://maps.google.com/embed",
        hasSandbox: true,
        isLazy: true,
      });
      assert.equal(sandboxEvaluation.outcome, "rejected");
      assert.equal(lazyEvaluation.outcome, "rejected");
    });
  });

  // ==========================================
  // Domain 7: Accessibility Form Inputs & Media
  // ==========================================
  describe("7. Accessibility Form Control & Media Candidate Validation", () => {
    it("rejects unlabelled candidate for non-interactive or self-labelling input types", () => {
      for (const type of ["hidden", "submit", "button", "reset", "image"]) {
        const evalResult = validateInputLabelCandidate({
          type,
          hasAria: false,
          hasTitle: false,
          hasLabelFor: false,
          isWrappedInLabel: false,
        });
        assert.equal(evalResult.outcome, "rejected", `Type ${type} must be rejected`);
      }
    });

    it("rejects unlabelled candidate when accessible name is provided via aria-label", () => {
      const evalResult = validateInputLabelCandidate({
        type: "text",
        hasAria: true,
        hasTitle: false,
        hasLabelFor: false,
        isWrappedInLabel: false,
      });
      assert.equal(evalResult.outcome, "rejected");
    });

    it("rejects unlabelled candidate when input is wrapped inside <label>", () => {
      const evalResult = validateInputLabelCandidate({
        type: "checkbox",
        hasAria: false,
        hasTitle: false,
        hasLabelFor: false,
        isWrappedInLabel: true,
      });
      assert.equal(evalResult.outcome, "rejected");
    });

    it("rejects unlabelled candidate when input has explicit <label for='...'> association", () => {
      const evalResult = validateInputLabelCandidate({
        type: "email",
        id: "user-email",
        hasAria: false,
        hasTitle: false,
        hasLabelFor: true,
        isWrappedInLabel: false,
      });
      assert.equal(evalResult.outcome, "rejected");
    });

    it("confirms unlabelled candidate when an interactive input has no accessible name", () => {
      const evalResult = validateInputLabelCandidate({
        type: "text",
        id: "mystery-input",
        hasAria: false,
        hasTitle: false,
        hasLabelFor: false,
        isWrappedInLabel: false,
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "a11y-inputs-unlabelled");
    });

    it("rejects missing alt candidate when image declares alt='' decorative text", () => {
      const evalResult = validateImageAltCandidate({
        hasAltAttribute: true,
        src: "decorative-spacer.png",
      });
      assert.equal(evalResult.outcome, "rejected");
    });

    it("confirms missing alt candidate when image completely lacks alt attribute", () => {
      const evalResult = validateImageAltCandidate({
        hasAltAttribute: false,
        src: "hero-photo.png",
      });
      assert.equal(evalResult.outcome, "confirmed");
      assert.equal(evalResult.ruleId, "a11y-images-missing-alt");
    });

    it("scanner integration: auditAccessibility honors candidate rejection for wrapped and decorative elements", () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <body>
            <label>Search site: <input type="search" /></label>
            <img src="/spacer.gif" alt="" />
          </body>
        </html>
      `;
      const a11yResult = auditAccessibility(html);
      const unlabelledFinding = a11yResult.findings.find((f) => f.id === "a11y-inputs-unlabelled");
      const missingAltFinding = a11yResult.findings.find((f) => f.id === "a11y-images-missing-alt");

      assert.equal(unlabelledFinding, undefined, "Wrapped input must not trigger unlabelled finding");
      assert.equal(missingAltFinding, undefined, "Image with alt='' must not trigger missing-alt finding");
    });
  });

  // ==========================================
  // Domain 8: SEO Canonicals
  // ==========================================
  describe("8. SEO Canonical Candidate Validation", () => {
    it("confirms missing canonical candidate when document contains zero canonicals", () => {
      const { missingEvaluation, multipleEvaluation } = validateCanonicalCandidate({
        canonicals: [],
      });
      assert.equal(missingEvaluation.outcome, "confirmed");
      assert.equal(missingEvaluation.ruleId, "seo-canonical-missing");
      assert.equal(multipleEvaluation, undefined);
    });

    it("rejects missing canonical candidate when a single canonical tag exists", () => {
      const { missingEvaluation, multipleEvaluation } = validateCanonicalCandidate({
        canonicals: ["https://example.com/page"],
      });
      assert.equal(missingEvaluation.outcome, "rejected");
      assert.equal(multipleEvaluation, undefined);
    });

    it("confirms multiple canonical candidate when 2 or more conflicting canonicals exist", () => {
      const { missingEvaluation, multipleEvaluation } = validateCanonicalCandidate({
        canonicals: ["https://example.com/page", "https://example.com/page?ref=1"],
      });
      assert.equal(missingEvaluation.outcome, "rejected");
      assert.ok(multipleEvaluation);
      assert.equal(multipleEvaluation.outcome, "confirmed");
      assert.equal(multipleEvaluation.ruleId, "seo-canonical-multiple");
    });

    it("scanner integration: auditSeo accurately records confirmed vs rejected canonical findings", () => {
      const htmlValid = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Valid SEO Page Title Here</title>
            <meta name="description" content="This is a comprehensive and descriptive page summary for search engine optimization testing." />
            <link rel="canonical" href="https://example.com/item" />
          </head>
          <body><h1>Heading</h1></body>
        </html>
      `;
      const resultValid = auditSeo(htmlValid);
      assert.equal(resultValid.findings.find((f) => f.id === "seo-canonical-missing"), undefined);
      assert.equal(resultValid.findings.find((f) => f.id === "seo-canonical-multiple"), undefined);
      assert.ok(resultValid.passedChecks.find((c) => c.id === "seo-canonical-present"));
    });
  });
});
