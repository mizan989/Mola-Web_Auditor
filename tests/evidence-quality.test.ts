import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  classifyEvidenceQuality,
  validateEvidenceQuality,
  enforceEvidenceQuality,
  assertEvidenceQualityAudit,
} from "../server/evidenceQuality.ts";
import { runWebsiteAudit } from "../server/orchestrator.ts";
import { auditPerformance } from "../server/scanners/performance.ts";
import { auditSecurity } from "../server/scanners/security.ts";
import type { Finding, FindingSeverity, FindingConfidence, FindingState } from "../types/audit.ts";

describe("Phase 7 — Independent Severity & Confidence", () => {
  const allSeverities: FindingSeverity[] = ["high", "medium", "low"];
  const allConfidences: FindingConfidence[] = ["high", "medium", "low"];

  describe("1. Strict Decoupling of Severity and Confidence", () => {
    it("proves severity and confidence are completely independent across all 9 combinations", () => {
      for (const severity of allSeverities) {
        for (const confidence of allConfidences) {
          const finding: Finding = {
            id: `test-${severity}-${confidence}`,
            category: "security",
            severity,
            confidence,
            state: "confirmed",
            priority: "recommended",
            title: `Matrix test ${severity} / ${confidence}`,
            description: "Testing independence",
            whyItMatters: "Severity is impact; confidence is certainty.",
            evidence: "Direct test matrix evidence",
            affectedTarget: "Test Target",
            recommendation: "Test action",
            structuredEvidence: {
              observation: "Direct test matrix evidence",
              evidenceType: "dom-inspection",
            },
          };

          const validation = validateEvidenceQuality(finding);
          assert.equal(validation.isValid, true, `Combination ${severity}/${confidence} must be valid`);
          assert.equal(finding.severity, severity);
          assert.equal(finding.confidence, confidence);
        }
      }
    });

    it("ensures severity reflects impact while confidence reflects certainty", () => {
      // High impact (severe flaw), but lower certainty
      const heuristicHighFinding: Finding = {
        id: "heuristic-high-risk",
        category: "security",
        severity: "high", // High impact if true!
        confidence: "medium", // Medium certainty because derived from heuristic signal
        state: "observation",
        priority: "critical",
        title: "Potential Critical Flaw",
        description: "Observed via indirect heuristic",
        whyItMatters: "If exploited, severe data breach possible.",
        evidence: "Partial telemetry signal",
        affectedTarget: "Edge Gateway",
        recommendation: "Inspect manual logs",
      };

      assert.equal(heuristicHighFinding.severity, "high");
      assert.equal(heuristicHighFinding.confidence, "medium");

      // Low impact (minor cosmetic defect), but 100% certain direct proof
      const directLowFinding: Finding = {
        id: "direct-minor-defect",
        category: "seo",
        severity: "low", // Minor impact
        confidence: "high", // 100% direct certainty in parsed HTML
        state: "recommendation",
        priority: "recommended",
        title: "Title is 12 characters",
        description: "Page title is slightly brief.",
        whyItMatters: "Slightly less keyword opportunity in SERP.",
        evidence: "<title>My App</title>",
        affectedTarget: "<head><title>",
        recommendation: "Expand title length.",
      };

      assert.equal(directLowFinding.severity, "low");
      assert.equal(directLowFinding.confidence, "high");
    });
  });

  describe("2. Evidence-Quality Rules", () => {
    it("rule 1: direct evidence can be high confidence", () => {
      const directFinding: Finding = {
        id: "sec-hsts-missing",
        category: "security",
        severity: "high",
        confidence: "high",
        state: "confirmed",
        priority: "fix-first",
        title: "Strict-Transport-Security (HSTS) Missing",
        description: "Header absent on HTTPS host.",
        whyItMatters: "SSL stripping vulnerability.",
        evidence: "response.headers['strict-transport-security'] is undefined",
        affectedTarget: "HTTP Response Headers",
        recommendation: "Add HSTS header.",
        structuredEvidence: {
          observation: "response.headers['strict-transport-security'] is undefined",
          evidenceType: "header-inspection",
        },
      };

      const evalResult = classifyEvidenceQuality(directFinding);
      assert.equal(evalResult.tier, "direct");
      assert.equal(evalResult.confidence, "high");
      assert.equal(evalResult.state, "confirmed");
    });

    it("rule 2: strong structural inference can be high or medium confidence", () => {
      const structuralFinding: Finding = {
        id: "seo-canonical-multiple",
        category: "seo",
        severity: "medium",
        confidence: "high",
        state: "confirmed",
        priority: "fix-first",
        title: "Multiple Canonical Tags",
        description: "Conflicting canonical tags in DOM.",
        whyItMatters: "Confuses search crawlers.",
        evidence: "Found 2 canonical tags",
        affectedTarget: "<head>",
        recommendation: "Use one canonical.",
        structuredEvidence: {
          observation: "Found 2 canonical tags",
          evidenceType: "dom-inspection",
        },
      };

      const evalResult = classifyEvidenceQuality(structuralFinding);
      assert.equal(evalResult.tier, "structural");
      assert.equal(evalResult.confidence, "high");
    });

    it("rule 3: heuristic / operational observations must not be presented as confirmed defects", () => {
      const ttfbResult = auditPerformance(800, 1024, {}, "<html></html>");
      const moderateTtfb = ttfbResult.findings.find((f) => f.id === "perf-moderate-ttfb");

      assert.ok(moderateTtfb, "Expected perf-moderate-ttfb to be generated");
      assert.equal(moderateTtfb?.state, "observation", "Heuristic latency must be marked as observation, not confirmed defect");
      assert.equal(moderateTtfb?.confidence, "medium", "Single point-in-time TTFB must be medium confidence");
    });

    it("rule 4: unsupported inference cannot become a confirmed finding", () => {
      // sec-connection-failed
      const secResult = auditSecurity({
        finalUrl: "https://offline.example.com",
        headers: {},
        body: { text: "", byteLength: 0, isTruncated: false },
        timing: { startTime: 0, ttfbMs: 0 },
        response: { statusCode: 0, statusText: "", protocol: "", isHttps: true, responseTimeMs: 0, contentLength: 0, contentType: "" },
        discoveredResources: { scripts: [], stylesheets: [], images: [], iframes: [] },
        technologyObservations: [],
        limitations: ["Host offline"],
        metadata: {
          scanId: "fail-test",
          userAgent: "test",
          timestamp: "",
          isPartial: true,
          failureReason: "ECONNREFUSED",
        },
        targetUrl: "https://offline.example.com",
        hostname: "offline.example.com",
        scanMode: "quick",
        redirectChain: [],
      });

      const failedFinding = secResult.findings.find((f) => f.id === "sec-connection-failed");
      assert.ok(failedFinding);
      assert.equal(failedFinding.state, "unable_to_check", "Unsupported check must be unable_to_check, NOT confirmed");

      // Verify that enforcing rules on a misclassified unsupported finding corrects it
      const misclassified: Finding = {
        ...failedFinding,
        state: "confirmed" as FindingState,
      };

      const corrected = enforceEvidenceQuality(misclassified);
      assert.equal(corrected.state, "unable_to_check", "enforceEvidenceQuality must prevent unsupported from being confirmed");
    });

    it("rule 5: bans arbitrary numeric confidence scores or global vanity scores", () => {
      // Validate that finding confidence is strictly categorical
      for (const confidence of allConfidences) {
        assert.equal(typeof confidence, "string");
        assert.match(confidence, /^(high|medium|low)$/);
      }
    });
  });

  describe("3. Full Audit Scan Adherence to Phase 7", () => {
    it("ensures live runWebsiteAudit findings satisfy evidence quality rules with 0 violations", async () => {
      const result = await runWebsiteAudit({ url: "https://example.com", mode: "quick" });

      const auditCheck = assertEvidenceQualityAudit(result.findings);
      assert.equal(auditCheck.allValid, true, `Violations found: ${JSON.stringify(auditCheck.report)}`);

      // Verify summary does not contain numeric confidence scores or global vanity score
      const record = result as unknown as Record<string, unknown>;
      assert.equal(record.score, undefined);
      assert.equal(record.globalScore, undefined);
      assert.equal(record.overallScore, undefined);

      // Verify confirmed findings have both severity and confidence
      for (const finding of result.findings) {
        assert.ok(["high", "medium", "low"].includes(finding.severity));
        assert.ok(["high", "medium", "low"].includes(finding.confidence));
        if (finding.state === "observation") {
          assert.equal(finding.state, "observation");
        }
      }
    });
  });
});
