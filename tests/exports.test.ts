import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateIssuesMarkdown,
  generateVerificationMarkdown,
} from "../lib/exportMarkdown.ts";
import type { ScanResult, VerificationComparison } from "../types/audit.ts";

describe("Export Markdown Generation (ISSUE-049)", () => {
  const mockResult: ScanResult = {
    scanId: "test-scan-123",
    targetUrl: "https://example.com",
    finalUrl: "https://example.com/",
    hostname: "example.com",
    scanTimestamp: "2026-10-07T12:00:00Z",
    scanDurationMs: 450,
    scanMode: "quick",
    status: "completed",
    completeness: "full",
    summary: {
      highCount: 1,
      mediumCount: 1,
      lowCount: 0,
      totalFindings: 2,
      passedCount: 8,
      categoryCounts: {
        security: 1,
        performance: 0,
        seo: 1,
        accessibility: 0,
        "best-practices": 0,
      },
    },
    findings: [
      {
        id: "sec-hsts-missing",
        category: "security",
        severity: "high",
        priority: "critical",
        title: "Strict-Transport-Security (HSTS) Header Missing",
        description: "The server did not send an HSTS header.",
        whyItMatters: "Allows SSL stripping attacks.",
        evidence: "Strict-Transport-Security header was not returned in HTTP response",
        affectedTarget: "HTTPS Response Headers",
        recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        codeSnippet: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      },
      {
        id: "seo-title-missing",
        category: "seo",
        severity: "medium",
        priority: "fix-first",
        title: "Page Title Missing",
        description: "The document lacks a <title> element.",
        whyItMatters: "Search engines and social link previews cannot identify page content.",
        evidence: "<title> tag was not found in parsed HTML",
        affectedTarget: "<head><title>",
        recommendation: "Add a descriptive <title> tag.",
      },
    ],
    passedChecks: [
      {
        id: "sec-https-enabled",
        category: "security",
        title: "HTTPS Enforced",
        detail: "Target connects securely over TLS.",
      },
    ],
    technologies: [
      {
        name: "Next.js",
        category: "Framework",
        confidence: 100,
        evidence: "X-Powered-By header",
      },
    ],
    httpInfo: {
      statusCode: 200,
      statusText: "OK",
      responseTimeMs: 82,
      contentLength: 40960,
      contentType: "text/html; charset=utf-8",
      protocol: "HTTP/1.1 (TLS)",
      isHttps: true,
      headers: {},
      redirectChain: ["https://example.com/"],
      isTruncated: false,
    },
    performanceMetrics: {
      ttfbMs: 82,
      totalPayloadKb: 40,
      compression: "gzip",
      cacheControl: "public, max-age=3600",
      scriptsCount: 2,
      stylesheetsCount: 1,
      imagesCount: 0,
    },
    seoData: {
      title: null,
      titleLength: 0,
      metaDescription: "Example description",
      descriptionLength: 19,
      canonicalUrl: "https://example.com/",
      robots: "index, follow",
      ogTitle: null,
      ogImage: null,
      h1Count: 1,
      headings: [{ level: 1, text: "Example Heading" }],
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
  };

  it("generates markdown with clear metadata and audit completeness", () => {
    const md = generateIssuesMarkdown(mockResult);
    assert.match(md, /# Audit Issues & Recommendations — example\.com/);
    assert.match(md, /> - Target: `https:\/\/example\.com`/);
    assert.match(md, /> - Mode: QUICK Scan \(Complete\)/);
    assert.match(md, /> - Total Findings: \*\*2\*\*/);
  });

  it("formats findings with ordered sections matching ISSUE-046", () => {
    const md = generateIssuesMarkdown(mockResult);
    // Severity and title
    assert.match(md, /### 1\. \[HIGH\] Strict-Transport-Security \(HSTS\) Header Missing/);
    // Description, why it matters, concrete evidence, recommendation
    assert.match(md, /\*\*Concrete Evidence:\*\*/);
    assert.match(md, /Strict-Transport-Security header was not returned in HTTP response/);
    assert.match(md, /\*\*Why It Matters\*\*:\s*Allows SSL stripping attacks\./i);
    assert.match(md, /\*\*Recommended Fix:\*\*/i);
    assert.match(md, /Add Strict-Transport-Security/);
  });

  it("includes technology stack section with evidence", () => {
    const md = generateIssuesMarkdown(mockResult);
    assert.match(md, /## Detected Technology Stack/);
    assert.match(md, /Next\.js/);
    assert.match(md, /X-Powered-By header/);
  });

  it("generates fix verification markdown report correctly", () => {
    const comparison: VerificationComparison = {
      previousScanTimestamp: "2026-10-07T11:00:00Z",
      newScanTimestamp: "2026-10-07T12:00:00Z",
      targetUrl: "https://example.com",
      resolvedFindings: [
        {
          id: "a11y-img-alt-missing",
          category: "accessibility",
          severity: "medium",
          priority: "fix-first",
          title: "Images Missing alt Attributes",
          description: "Fixed on rescan.",
          whyItMatters: "A11y",
          evidence: "alt attributes present",
          recommendation: "Good job",
        },
      ],
      remainingFindings: mockResult.findings,
      changedFindings: [],
      newFindings: [],
      totalPrevious: 3,
      totalCurrent: 2,
    };

    const md = generateVerificationMarkdown(comparison);
    assert.match(md, /# Fix Verification Report — https:\/\/example\.com/);
    assert.match(md, /Resolved \(Fixed\): \*\*1\*\*/);
    assert.match(md, /Images Missing alt Attributes/);
    assert.match(md, /Still Present: \*\*2\*\*/);
  });
});
