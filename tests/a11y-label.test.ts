import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { auditAccessibility } from "../server/scanners/a11y.ts";

describe("Accessibility Form Label Auditing (ISSUE-020, ISSUE-021)", () => {
  it("flags inputs that have only an id attribute without an accessible name", () => {
    const html = `
      <!DOCTYPE html>
      <html lang="en">
        <head><title>Test</title></head>
        <body>
          <main>
            <input type="text" id="username" name="user" />
          </main>
        </body>
      </html>
    `;
    const result = auditAccessibility(html);
    const unlabelledFinding = result.findings.find((f) => f.id === "a11y-inputs-unlabelled");
    assert.ok(unlabelledFinding, "Expected unlabelled input finding to be raised");
    assert.equal(unlabelledFinding?.instancesCount, 1);
  });

  it("passes inputs associated with <label for=\"...\">", () => {
    const html = `
      <!DOCTYPE html>
      <html lang="en">
        <head><title>Test</title></head>
        <body>
          <main>
            <label for="username">Username</label>
            <input type="text" id="username" name="user" />
          </main>
        </body>
      </html>
    `;
    const result = auditAccessibility(html);
    const unlabelledFinding = result.findings.find((f) => f.id === "a11y-inputs-unlabelled");
    assert.equal(unlabelledFinding, undefined, "Expected no unlabelled finding");
    const passedCheck = result.passedChecks.find((p) => p.id === "a11y-inputs-labelled");
    assert.ok(passedCheck, "Expected passed check for labelled inputs");
  });

  it("passes inputs wrapped inside a <label>", () => {
    const html = `
      <!DOCTYPE html>
      <html lang="en">
        <head><title>Test</title></head>
        <body>
          <main>
            <label>
              Search
              <input type="search" name="q" />
            </label>
          </main>
        </body>
      </html>
    `;
    const result = auditAccessibility(html);
    const unlabelledFinding = result.findings.find((f) => f.id === "a11y-inputs-unlabelled");
    assert.equal(unlabelledFinding, undefined, "Expected wrapped input to be considered labelled");
  });

  it("passes inputs with aria-label or title attributes", () => {
    const html = `
      <!DOCTYPE html>
      <html lang="en">
        <head><title>Test</title></head>
        <body>
          <main>
            <input type="search" aria-label="Site Search" />
            <input type="text" title="Enter your zip code" />
          </main>
        </body>
      </html>
    `;
    const result = auditAccessibility(html);
    const unlabelledFinding = result.findings.find((f) => f.id === "a11y-inputs-unlabelled");
    assert.equal(unlabelledFinding, undefined, "Expected aria-label and title to provide accessible names");
  });

  it("ignores non-interactive or self-labelled input types (submit, hidden, button)", () => {
    const html = `
      <!DOCTYPE html>
      <html lang="en">
        <head><title>Test</title></head>
        <body>
          <main>
            <input type="hidden" name="csrf" value="token123" />
            <input type="submit" value="Submit Form" />
            <input type="button" value="Click Me" />
          </main>
        </body>
      </html>
    `;
    const result = auditAccessibility(html);
    const unlabelledFinding = result.findings.find((f) => f.id === "a11y-inputs-unlabelled");
    assert.equal(unlabelledFinding, undefined, "Expected hidden/submit/button to be excluded");
  });
});
