import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseHtmlDocument,
  cleanText,
  extractDocumentTitle,
  extractMetaDescription,
  extractCanonicalLinks,
  extractViewportMeta,
  extractOpenGraphMeta,
  extractRobotsMeta,
  extractHeadings,
  extractHtmlLanguage,
  extractImageAccessibility,
  extractFormLabels,
  extractLandmarks,
  extractDiscoveredResourcesFromDom,
  extractScripts,
  extractIframes,
  extractLinks,
  extractInsecureMixedContent,
  extractDeprecatedTags,
  extractHtmlCharset,
} from "../server/htmlParser.ts";
import { auditSeo } from "../server/scanners/seo.ts";
import { auditAccessibility } from "../server/scanners/a11y.ts";
import { auditBestPractices } from "../server/scanners/bestPractices.ts";
import { auditDeepScan } from "../server/scanners/deep.ts";
import { auditSecurity } from "../server/scanners/security.ts";

describe("Phase 4 — Structured HTML Parser & DOM Extraction", () => {
  describe("1. Deceptive / Misleading Strings Inside Scripts & Styles", () => {
    it("ignores deceptive HTML strings inside <script> and <style> blocks", () => {
      const deceptiveHtml = `<!DOCTYPE html>
      <html lang="en">
        <head>
          <title>Authentic Title</title>
          <script>
            // Deceptive markup inside client JavaScript
            const fakeTitle = "<title>Deceptive Title In JS</title>";
            const fakeCanonical = '<link rel="canonical" href="https://evil.com/fake">';
            const fakeScript = '<script src="http://insecure-cdn.example.com/malicious.js"></' + 'script>';
            const fakeImg = '<img src="http://insecure.example.com/tracker.gif">';
            const fakeInput = '<input id="fake-input" name="fake">';
            const fakeDeprecated = '<marquee>Fake Marquee</marquee>';
          </script>
          <style>
            /* Deceptive markup in CSS comments */
            /* <img src="http://insecure.example.com/css.png"> */
            /* <h1>Fake H1 In CSS</h1> */
          </style>
          <link rel="canonical" href="https://example.com/real-canonical">
        </head>
        <body>
          <h1>Authentic Primary Heading</h1>
        </body>
      </html>`;

      const root = parseHtmlDocument(deceptiveHtml);

      // Title should strictly be the authentic title
      const { rawTitle, count: titleCount } = extractDocumentTitle(root);
      assert.equal(rawTitle, "Authentic Title");
      assert.equal(titleCount, 1);

      // Canonical should strictly be the authentic canonical
      const { canonicalUrl, canonicals } = extractCanonicalLinks(root);
      assert.equal(canonicalUrl, "https://example.com/real-canonical");
      assert.equal(canonicals.length, 1);

      // Headings should only reflect authentic body elements
      const { headings, h1Count, h1Instances } = extractHeadings(root);
      assert.equal(h1Count, 1);
      assert.equal(h1Instances[0], "Authentic Primary Heading");

      // No mixed content should be flagged from strings inside scripts
      const mixed = extractInsecureMixedContent(root);
      assert.equal(mixed.length, 0);

      // No deprecated tags should be found from JS strings
      const deprecated = extractDeprecatedTags(root);
      assert.equal(deprecated.length, 0);

      // Discovered resources should not contain script strings
      const resources = extractDiscoveredResourcesFromDom(root);
      assert.equal(resources.images.length, 0);
      assert.equal(resources.scripts.length, 0); // Inline script without src
    });
  });

  describe("2. Malformed HTML Handling Without Crashing", () => {
    it("safely handles unclosed tags, missing bodies, and dangling elements", () => {
      const malformed = `
        <!doctype html>
        <html lang="es">
        <head>
          <title>Broken Document Title
          <meta name="description" content="Broken meta description unclosed
        <body>
          <h1>Unclosed H1 Tag
          <h2>Subheading
          <p>Unclosed paragraph with <img src="/broken.png"> and an unclosed link <a href="/test">link
          <div><span>Nested unclosed tags
      `;

      const root = parseHtmlDocument(malformed);
      assert.ok(root, "Root element must be produced without throwing");

      const { rawTitle } = extractDocumentTitle(root);
      assert.ok(rawTitle?.includes("Broken Document Title"));

      const { hasLang, lang } = extractHtmlLanguage(root);
      assert.equal(hasLang, true);
      assert.equal(lang, "es");

      const { headings } = extractHeadings(root);
      assert.ok(headings.length >= 2);
      assert.equal(headings[0].level, 1);
      assert.equal(headings[1].level, 2);

      const images = extractImageAccessibility(root);
      assert.equal(images.totalImages, 1);
      assert.equal(images.missingAlt.length, 1);
    });

    it("safely handles empty, null, or extreme whitespace input", () => {
      const emptyRoot = parseHtmlDocument("");
      assert.ok(emptyRoot);
      const titleRes = extractDocumentTitle(emptyRoot);
      assert.equal(titleRes.rawTitle, null);
      assert.equal(titleRes.count, 0);

      const whitespaceRoot = parseHtmlDocument("   \n\t   ");
      assert.ok(whitespaceRoot);
      assert.equal(extractDocumentTitle(whitespaceRoot).rawTitle, null);
    });
  });

  describe("3. Nested Labels vs Explicit 'for' Attribute Form Inputs", () => {
    it("distinguishes between nested labels, external for attributes, and unlabelled controls", () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head><title>Form Test</title></head>
          <body>
            <main>
              <!-- 1. Explicit association via label for -->
              <label for="first-name">First Name</label>
              <input type="text" id="first-name" name="first" />

              <!-- 2. Nested input inside label -->
              <label>
                Email Address
                <input type="email" name="email" />
              </label>

              <!-- 3. ARIA labelled input -->
              <input type="search" aria-label="Search Catalog" />

              <!-- 4. Title labelled input -->
              <input type="text" title="ZIP or Postal Code" />

              <!-- 5. Unlabelled input (id alone does NOT count as label) -->
              <input type="text" id="unlabelled-account" name="account" />

              <!-- 6. Ignored buttons and hidden tokens -->
              <input type="hidden" name="token" value="xyz" />
              <input type="submit" value="Submit" />
            </main>
          </body>
        </html>
      `;

      const root = parseHtmlDocument(html);
      const formLabels = extractFormLabels(root);

      assert.equal(formLabels.totalInputs, 5); // Excludes hidden and submit
      assert.equal(formLabels.unlabelledInputs, 1);
      assert.ok(formLabels.unlabelledSamples[0].includes("unlabelled-account"));
    });
  });

  describe("4. Duplicate ID Detection", () => {
    it("flags duplicate element IDs that break label associations and accessibility", () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head><title>Duplicate IDs</title></head>
          <body>
            <main>
              <div id="duplicate-widget">Widget 1</div>
              <div id="duplicate-widget">Widget 2</div>
              <input type="text" id="user-field" aria-label="User 1" />
              <input type="text" id="user-field" aria-label="User 2" />
              <span id="unique-span">Unique</span>
            </main>
          </body>
        </html>
      `;

      const root = parseHtmlDocument(html);
      const formLabels = extractFormLabels(root);

      assert.ok(formLabels.duplicateIds.includes("duplicate-widget"));
      assert.ok(formLabels.duplicateIds.includes("user-field"));
      assert.equal(formLabels.duplicateIds.includes("unique-span"), false);

      const a11yResult = auditAccessibility(html);
      const duplicateFinding = a11yResult.findings.find((f) => f.id === "a11y-duplicate-ids");
      assert.ok(duplicateFinding, "Expected a11y-duplicate-ids finding to be reported");
      assert.equal(duplicateFinding?.severity, "medium");
      assert.equal(duplicateFinding?.instancesCount, 2);
    });
  });

  describe("5. Multiple Canonical Link Tags", () => {
    it("detects and flags conflicting multiple canonical link tags", () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <title>Multiple Canonicals Page</title>
            <link rel="canonical" href="https://example.com/primary">
            <link rel="canonical" href="https://example.com/secondary">
          </head>
          <body>
            <h1>Heading</h1>
          </body>
        </html>
      `;

      const root = parseHtmlDocument(html);
      const { canonicalUrl, canonicals } = extractCanonicalLinks(root);

      assert.equal(canonicalUrl, "https://example.com/primary");
      assert.equal(canonicals.length, 2);
      assert.deepEqual(canonicals, [
        "https://example.com/primary",
        "https://example.com/secondary",
      ]);

      const seoResult = auditSeo(html);
      const multipleFinding = seoResult.findings.find((f) => f.id === "seo-canonical-multiple");
      assert.ok(multipleFinding, "Expected seo-canonical-multiple finding for conflicting canonicals");
      assert.equal(multipleFinding?.state, "confirmed");
      assert.equal(multipleFinding?.instancesCount, 2);
    });
  });

  describe("6. Relative vs. Absolute Resources & Subresource Inspections", () => {
    it("correctly identifies external vs relative scripts and verifies SRI attributes", () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <title>Resource Inspection</title>
            <!-- Relative internal scripts -->
            <script src="/static/app.js"></script>
            <script src="./local.js"></script>
            <!-- Third-party scripts: one with SRI, one without -->
            <script src="https://cdn.example.org/secure-lib.js" integrity="sha384-abc123def" crossorigin="anonymous"></script>
            <script src="https://cdn.example.org/insecure-lib.js"></script>
            <!-- Insecure mixed content on HTTPS -->
            <script src="http://unencrypted.example.com/tracker.js"></script>
            <!-- Stylesheets -->
            <link rel="stylesheet" href="/styles/main.css">
            <link rel="stylesheet" href="https://fonts.example.com/font.css">
          </head>
          <body>
            <img src="/img/local.png" alt="Local Image">
            <img src="https://cdn.example.org/remote.png" alt="Remote Image">
            <iframe src="https://player.example.com/embed" sandbox="allow-scripts" loading="lazy"></iframe>
            <iframe src="https://widget.example.com/frame"></iframe>
          </body>
        </html>
      `;

      const root = parseHtmlDocument(html);
      const resources = extractDiscoveredResourcesFromDom(root);

      assert.equal(resources.scripts.length, 5);
      assert.equal(resources.stylesheets.length, 2);
      assert.equal(resources.images.length, 2);
      assert.equal(resources.iframes.length, 2);

      // Deep scan check with mock host https://example.com
      const deepResult = auditDeepScan(
        { "set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax" },
        "https://example.com",
        html
      );

      // External scripts without SRI should only flag insecure-lib.js and tracker.js
      const sriFinding = deepResult.findings.find((f) => f.id === "sec-sri-missing");
      assert.ok(sriFinding);
      assert.ok(
        (sriFinding?.structuredEvidence?.metadata?.instances as string[]).includes(
          "https://cdn.example.org/insecure-lib.js"
        )
      );
      assert.ok(
        !(sriFinding?.structuredEvidence?.metadata?.instances as string[]).includes(
          "https://cdn.example.org/secure-lib.js"
        )
      );

      // Iframes: second iframe lacks sandbox and lazy loading
      const iframeSandboxFinding = deepResult.findings.find(
        (f) => f.id === "sec-iframe-sandbox-missing"
      );
      assert.ok(iframeSandboxFinding);
      assert.equal(iframeSandboxFinding?.instancesCount, 1);

      // Mixed content check on HTTPS target
      const secResult = auditSecurity({}, "https://example.com", html);
      const mixedFinding = secResult.findings.find((f) => f.id === "sec-mixed-content");
      assert.ok(mixedFinding);
      assert.ok(
        (mixedFinding?.structuredEvidence?.metadata?.sampleSources as string[]).includes(
          "http://unencrypted.example.com/tracker.js"
        )
      );
    });
  });

  describe("7. Response-Size Limit Preservation (2.5MB)", () => {
    it("safely bounds memory consumption on oversized documents without throwing", () => {
      // Create a payload larger than 2.5MB
      const hugePadding = "<!-- " + "x".repeat(3 * 1024 * 1024) + " -->";
      const hugeHtml = `<!DOCTYPE html><html lang="en"><head><title>Large Document</title></head><body><h1>Heading</h1>${hugePadding}</body></html>`;

      const root = parseHtmlDocument(hugeHtml);
      assert.ok(root, "Parser must handle oversized input gracefully");

      const { rawTitle } = extractDocumentTitle(root);
      assert.equal(rawTitle, "Large Document");
    });
  });

  describe("8. Text Cleaning and HTML Entity Normalization", () => {
    it("cleans HTML entities and collapses whitespace in titles and headings", () => {
      const raw = "  &lt;Awesome&gt; &amp; &quot;Incredible&quot;   Web&#39;s App &nbsp; ";
      const cleaned = cleanText(raw);
      assert.equal(cleaned, '<Awesome> & "Incredible" Web\'s App');
    });
  });

  describe("9. Deprecated Tag Detection in DOM", () => {
    it("detects genuine deprecated tags in DOM while ignoring comments and strings", () => {
      const html = `
        <!DOCTYPE html>
        <html lang="en">
          <head><title>Deprecated Test</title></head>
          <body>
            <!-- <blink>Commented blink</blink> -->
            <center>
              <font color="red">Old Font</font>
              <marquee>Scrolling text</marquee>
            </center>
          </body>
        </html>
      `;

      const bpResult = auditBestPractices(html);
      const deprecatedFinding = bpResult.findings.find((f) => f.id === "bp-deprecated-tags");
      assert.ok(deprecatedFinding);
      const foundTags = deprecatedFinding?.structuredEvidence?.metadata?.foundDeprecated as string[];
      assert.ok(foundTags.includes("<center>"));
      assert.ok(foundTags.includes("<font>"));
      assert.ok(foundTags.includes("<marquee>"));
      assert.ok(!foundTags.includes("<blink>")); // Was only in comment
    });
  });
});
