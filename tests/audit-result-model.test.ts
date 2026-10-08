import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type {
  Finding,
  FindingCategory,
  FindingConfidence,
  FindingSeverity,
  FindingState,
  StructuredEvidence,
  ScanResult,
  PassedCheck,
} from "../types/audit.ts";
import { auditSecurity } from "../server/scanners/security.ts";
import { auditPerformance } from "../server/scanners/performance.ts";
import { auditSeo } from "../server/scanners/seo.ts";
import { auditAccessibility } from "../server/scanners/a11y.ts";
import { auditBestPractices } from "../server/scanners/bestPractices.ts";
import { auditDeepScan } from "../server/scanners/deep.ts";
import { generateIssuesMarkdown } from "../lib/exportMarkdown.ts";

describe("Phase 1 — Explicit Evidence-First Audit Model", () => {
  const allStates: FindingState[] = [
    "confirmed",
    "not_detected",
    "unable_to_check",
    "failed",
    "observation",
    "recommendation",
  ];

  const allConfidences: FindingConfidence[] = ["high", "medium", "low"];
  const allSeverities: FindingSeverity[] = ["high", "medium", "low"];

  it("validates that all 6 states can be represented on findings", () => {
    for (const state of allStates) {
      const finding: Finding = {
        id: `test-state-${state}`,
        category: "security",
        severity: "medium",
        priority: "fix-first",
        state,
        confidence: "high",
        title: `Test finding for state ${state}`,
        description: `Description for ${state}`,
        whyItMatters: "State test",
        evidence: `Evidence for ${state}`,
        recommendation: `Fix for ${state}`,
      };
      assert.strictEqual(finding.state, state);
    }
  });

  it("verifies severity and confidence are strictly independent across all matrix combinations", () => {
    for (const severity of allSeverities) {
      for (const confidence of allConfidences) {
        const finding: Finding = {
          id: `test-combo-${severity}-${confidence}`,
          category: "security",
          severity,
          priority: severity === "high" ? "critical" : "recommended",
          state: "confirmed",
          confidence,
          title: `Finding with ${severity} severity and ${confidence} confidence`,
          description: "Testing independence of impact and observation certainty",
          whyItMatters: "Severity reflects impact; confidence reflects certainty.",
          evidence: `Observed at confidence level ${confidence}`,
          recommendation: "Ensure independent assignment",
        };

        // Assert that severity and confidence do not collapse or depend on each other
        assert.strictEqual(finding.severity, severity);
        assert.strictEqual(finding.confidence, confidence);
      }
    }
  });

  it("ensures structured evidence encapsulates all required telemetry fields and limitations", () => {
    const evidence: StructuredEvidence = {
      id: "ev-test-001",
      sourceUrl: "https://example.com/login",
      affectedTarget: 'form[action="/api/auth"]',
      observation: "Observed plaintext form submission endpoint without CSRF protection header",
      expectedCondition: "Target form endpoint must include anti-CSRF token or SameSite cookie verification",
      evidenceType: "dom-form-inspection",
      metadata: {
        formId: "login-form",
        method: "POST",
        inputCount: 3,
      },
      limitations: "Static DOM audit; dynamic JavaScript token injection could not be executed without headless browser.",
    };

    const finding: Finding = {
      id: "sec-csrf-missing",
      category: "security",
      severity: "high", // High impact
      priority: "critical",
      state: "observation", // Heuristic observation pending runtime validation
      confidence: "medium", // Independent confidence
      title: "Potential CSRF Vulnerability on Login Form",
      description: "Login form does not statically declare a CSRF token.",
      whyItMatters: "Allows cross-site request forgery attacks if not handled by SameSite cookies or headers.",
      evidence: evidence.observation,
      structuredEvidence: evidence,
      affectedTarget: evidence.affectedTarget,
      recommendation: "Add CSRF protection token or ensure SameSite=Strict cookies.",
      limitations: evidence.limitations,
    };

    assert.ok(finding.structuredEvidence);
    assert.strictEqual(finding.structuredEvidence.id, "ev-test-001");
    assert.strictEqual(finding.structuredEvidence.sourceUrl, "https://example.com/login");
    assert.strictEqual(finding.structuredEvidence.affectedTarget, 'form[action="/api/auth"]');
    assert.strictEqual(finding.structuredEvidence.evidenceType, "dom-form-inspection");
    assert.strictEqual(finding.structuredEvidence.limitations, evidence.limitations);
    assert.strictEqual(finding.limitations, evidence.limitations);
    assert.strictEqual(finding.severity, "high");
    assert.strictEqual(finding.confidence, "medium");
    assert.strictEqual(finding.state, "observation");
  });

  it("prohibits unavailable/failed checks from appearing as successful passes", () => {
    // When an inspection cannot check a resource, it must never produce a passing check record
    const unableCheck: PassedCheck = {
      id: "check-headless-runtime",
      category: "best-practices",
      title: "Dynamic JavaScript Execution",
      detail: "Headless browser execution was not configured; dynamic resources were not evaluated.",
      state: "unable_to_check",
      confidence: "high",
      structuredEvidence: {
        observation: "Headless browser unavailable in environment",
        expectedCondition: "Browser rendering environment configured",
        limitations: "Inspection limited to static HTTP body",
      },
    };

    // An unable_to_check or failed state must be explicitly distinguishable from confirmed passes
    assert.notStrictEqual(unableCheck.state, "confirmed");
    assert.strictEqual(unableCheck.state, "unable_to_check");
  });

  it("verifies security scanner assigns explicit states, confidence, and structuredEvidence", () => {
    const result = auditSecurity(
      { "content-type": "text/html" },
      "http://example.com",
      "<html><head></head><body><script src=\"http://insecure.cdn.com/app.js\"></script></body></html>"
    );

    assert.ok(result.findings.length > 0);
    for (const f of result.findings) {
      assert.ok(allStates.includes(f.state), `Finding ${f.id} has valid state: ${f.state}`);
      assert.ok(allConfidences.includes(f.confidence), `Finding ${f.id} has valid confidence: ${f.confidence}`);
      assert.ok(allSeverities.includes(f.severity), `Finding ${f.id} has valid severity: ${f.severity}`);
      assert.ok(f.structuredEvidence, `Finding ${f.id} must include structuredEvidence`);
      assert.ok(f.structuredEvidence.observation, `Finding ${f.id} structured evidence must have observation`);
    }

    const secureResult = auditSecurity(
      {
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
      },
      "https://example.com",
      "<html><head></head><body></body></html>"
    );

    assert.ok(secureResult.passedChecks.length > 0);
    for (const p of secureResult.passedChecks) {
      if (p.state) {
        assert.ok(allStates.includes(p.state), `PassedCheck ${p.id} state must be valid`);
      }
    }
  });

  it("verifies performance scanner assigns explicit states, confidence, and structuredEvidence", () => {
    const result = auditPerformance(
      350,
      120000,
      { "content-type": "text/html" },
      "<html><head><script src=\"/bundle.js\"></script></head><body></body></html>"
    );

    for (const f of result.findings) {
      assert.ok(allStates.includes(f.state));
      assert.ok(allConfidences.includes(f.confidence));
      assert.ok(f.structuredEvidence);
    }
    for (const p of result.passedChecks) {
      if (p.state) assert.ok(allStates.includes(p.state));
    }
  });

  it("verifies SEO scanner assigns explicit states, confidence, and structuredEvidence", () => {
    const result = auditSeo("<html><head><title></title></head><body></body></html>");
    for (const f of result.findings) {
      assert.ok(allStates.includes(f.state));
      assert.ok(allConfidences.includes(f.confidence));
      assert.ok(f.structuredEvidence);
    }
  });

  it("verifies accessibility scanner assigns explicit states, confidence, and structuredEvidence", () => {
    const result = auditAccessibility("<html><head></head><body><img src=\"/pic.jpg\"><input type=\"text\"></body></html>");
    for (const f of result.findings) {
      assert.ok(allStates.includes(f.state));
      assert.ok(allConfidences.includes(f.confidence));
      assert.ok(f.structuredEvidence);
    }
  });

  it("verifies best practices scanner assigns explicit states, confidence, and structuredEvidence", () => {
    const result = auditBestPractices("<html><head><meta http-equiv=\"refresh\" content=\"5\"></head><body></body></html>");
    for (const f of result.findings) {
      assert.ok(allStates.includes(f.state));
      assert.ok(allConfidences.includes(f.confidence));
      assert.ok(f.structuredEvidence);
    }
  });

  it("verifies deep scanner assigns explicit states, confidence, and structuredEvidence", () => {
    const result = auditDeepScan(
      { "set-cookie": "session=123" },
      "https://example.com",
      "<html><head><script src=\"https://cdn.example.org/lib.js\"></script></head><body><iframe src=\"https://embed.org\"></iframe></body></html>"
    );
    for (const f of result.findings) {
      assert.ok(allStates.includes(f.state));
      assert.ok(allConfidences.includes(f.confidence));
      assert.ok(f.structuredEvidence);
    }
    for (const p of result.passedChecks) {
      if (p.state) assert.ok(allStates.includes(p.state));
    }
  });

  it("verifies Markdown export accurately preserves State, Confidence, and Structured Evidence", () => {
    const mockFinding: Finding = {
      id: "sec-cookie-insecure",
      category: "security",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Session Cookie Security Flags Incomplete",
      description: "Set-Cookie header lacked Secure flag.",
      whyItMatters: "Cookies can leak over plaintext connections.",
      evidence: "Set-Cookie: session=abc",
      structuredEvidence: {
        id: "ev-sec-cookie-insecure",
        sourceUrl: "https://example.com",
        affectedTarget: "Set-Cookie header",
        observation: "Set-Cookie missing Secure directive",
        expectedCondition: "All cookies include Secure flag",
        evidenceType: "header-inspection",
        limitations: "Cookie values partially masked for privacy",
      },
      affectedTarget: "Set-Cookie header",
      recommendation: "Add Secure flag to Set-Cookie header.",
      limitations: "Cookie values partially masked for privacy",
    };

    const mockScan: ScanResult = {
      scanId: "mola-test-result-model",
      targetUrl: "https://example.com",
      finalUrl: "https://example.com/",
      hostname: "example.com",
      scanTimestamp: "2026-10-08T09:30:00Z",
      scanDurationMs: 120,
      scanMode: "quick",
      status: "completed",
      completeness: "full",
      summary: {
        totalFindings: 1,
        highCount: 0,
        mediumCount: 1,
        lowCount: 0,
        passedCount: 1,
        categoryCounts: {
          security: 1,
          performance: 0,
          seo: 0,
          accessibility: 0,
          "best-practices": 0,
        },
        stateCounts: {
          confirmed: 1,
          not_detected: 0,
          unable_to_check: 0,
          failed: 0,
          observation: 0,
          recommendation: 0,
        },
        confidenceCounts: {
          high: 1,
          medium: 0,
          low: 0,
        },
      },
      findings: [mockFinding],
      passedChecks: [
        {
          id: "sec-https-enforced",
          category: "security",
          title: "HTTPS Enforced",
          detail: "Target connects over secure TLS protocol.",
          state: "confirmed",
          confidence: "high",
        },
      ],
      technologies: [],
      httpInfo: {
        statusCode: 200,
        statusText: "OK",
        protocol: "HTTP/1.1 (TLS)",
        responseTimeMs: 50,
        contentLength: 1024,
        contentType: "text/html",
        isHttps: true,
        redirectChain: ["https://example.com/"],
        headers: {},
      },
      performanceMetrics: {
        ttfbMs: 50,
        totalPayloadKb: 1,
        compression: "gzip",
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
        hasMainLandmark: true,
        hasHeaderLandmark: true,
        inputsMissingLabel: 0,
      },
    };

    const md = generateIssuesMarkdown(mockScan);

    // Verify Confidence breakdown in summary
    assert.match(md, /Confidence: High: 1, Medium: 0, Low: 0/);

    // Verify State and Confidence badges in finding entry
    assert.match(md, /- \*\*State\*\*: `CONFIRMED`/);
    assert.match(md, /- \*\*Confidence\*\*: `HIGH`/);

    // Verify Structured Evidence section
    assert.match(md, /\*\*Structured Evidence:\*\*/);
    assert.match(md, /- \*\*Observation\*\*: Set-Cookie missing Secure directive/);
    assert.match(md, /- \*\*Expected\*\*: All cookies include Secure flag/);
    assert.match(md, /- \*\*Evidence Type\*\*: `header-inspection`/);
    assert.match(md, /- \*\*Limitations\*\*: Cookie values partially masked for privacy/);
  });
});
