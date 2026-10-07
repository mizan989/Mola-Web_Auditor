import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectTechnologies } from "../server/scanners/tech.ts";

describe("Technology Detection (ISSUE-015, ISSUE-016)", () => {
  it("detects Next.js with verifiable evidence from headers and HTML markers", () => {
    const headers = { "x-powered-by": "Next.js" };
    const html = `
      <!DOCTYPE html>
      <html>
        <head><script src="/_next/static/chunks/main-app.js"></script></head>
        <body><div id="__next">Hello</div></body>
      </html>
    `;
    const techs = detectTechnologies(headers, html);
    const nextTech = techs.find((t) => t.name === "Next.js");
    assert.ok(nextTech, "Expected Next.js to be detected");
    assert.equal(nextTech?.category, "Framework");
    assert.ok(nextTech?.confidence && nextTech.confidence >= 95);
    assert.ok(nextTech?.evidence && nextTech.evidence.length > 0);
  });

  it("does not false-positive React from English text containing 'reaction' or 'reacting'", () => {
    const headers = {};
    const html = `
      <!DOCTYPE html>
      <html>
        <body>
          <p>This is a chemical reaction demonstration with reacting substances.</p>
        </body>
      </html>
    `;
    const techs = detectTechnologies(headers, html);
    const reactTech = techs.find((t) => t.name === "React");
    assert.equal(reactTech, undefined, "Must not detect React from words like 'reaction' or 'reacting'");
  });

  it("detects React when authentic script or root elements exist", () => {
    const headers = {};
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"></script>
        </head>
        <body><div data-reactroot="">Content</div></body>
      </html>
    `;
    const techs = detectTechnologies(headers, html);
    const reactTech = techs.find((t) => t.name === "React");
    assert.ok(reactTech, "Expected React to be detected from genuine script tag");
    assert.ok(reactTech?.evidence);
  });

  it("detects Tailwind CSS from dedicated stylesheet or CDN link", () => {
    const headers = {};
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body><div class="p-4">Content</div></body>
      </html>
    `;
    const techs = detectTechnologies(headers, html);
    const twTech = techs.find((t) => t.name === "Tailwind CSS");
    assert.ok(twTech, "Expected Tailwind CSS to be detected from CDN");
    assert.match(twTech?.evidence || "", /cdn/i);
  });

  it("does not confirm Tailwind CSS from a single isolated utility class name alone", () => {
    const headers = {};
    const html = `
      <!DOCTYPE html>
      <html>
        <body>
          <div class="flex">Simple flex box</div>
        </body>
      </html>
    `;
    const techs = detectTechnologies(headers, html);
    const twTech = techs.find((t) => t.name === "Tailwind CSS");
    assert.equal(twTech, undefined, "Single class name 'flex' alone must not trigger Tailwind confirmation");
  });

  it("detects Tailwind CSS from high-confidence class clusters", () => {
    const headers = {};
    const html = `
      <!DOCTYPE html>
      <html>
        <body>
          <div class="grid sm:grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6 p-4 rounded-xl shadow-lg hover:shadow-2xl transition-all">
            Card
          </div>
        </body>
      </html>
    `;
    const techs = detectTechnologies(headers, html);
    const twTech = techs.find((t) => t.name === "Tailwind CSS");
    assert.ok(twTech, "Expected Tailwind CSS to be detected from distinctive class cluster");
  });
});
