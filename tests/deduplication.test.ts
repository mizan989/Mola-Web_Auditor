import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateCorrelationKey,
  isSemanticDuplicate,
  mergeDuplicateFindings,
  deduplicateFindings,
  correlateFindings,
  normalizeTarget,
  normalizeCondition,
} from "../server/deduplication.ts";
import { runWebsiteAudit } from "../server/orchestrator.ts";
import type { Finding } from "../types/audit.ts";

describe("Phase 9 — Finding Deduplication & Semantic Correlation", () => {
  const baseFinding: Finding = {
    id: "sec-sri-missing",
    category: "security",
    severity: "medium",
    priority: "fix-first",
    state: "confirmed",
    confidence: "high",
    title: "Third-Party Scripts Missing Subresource Integrity (SRI)",
    description: "Detected external script without SRI.",
    whyItMatters: "Adversaries can tamper with CDN scripts.",
    evidence: "Sample script without SRI: https://cdn.example.com/lib.js",
    affectedTarget: "https://cdn.example.com/lib.js",
    recommendation: "Add sha384 or sha512 integrity hashes.",
    structuredEvidence: {
      observation: "Script tag missing integrity attribute",
      expectedCondition: "External third-party scripts include sha384 integrity hashes",
      evidenceType: "html-script-inspection",
      metadata: { count: 1 },
    },
    instances: ["https://cdn.example.com/lib.js"],
    instancesCount: 1,
  };

  describe("1. Deterministic Semantic Correlation Key Generation", () => {
    it("generates deterministic keys from category, rule ID, target, and condition", () => {
      const key1 = generateCorrelationKey(baseFinding);
      const key2 = generateCorrelationKey({ ...baseFinding });
      assert.equal(key1, key2);
      assert.ok(key1.includes("security"));
      assert.ok(key1.includes("sec-sri-missing"));
      assert.ok(key1.includes("https://cdn.example.com/lib.js"));
    });

    it("normalizes target URLs by stripping trailing slashes and query strings", () => {
      const targetA = normalizeTarget("https://cdn.example.com/lib.js/");
      const targetB = normalizeTarget("https://cdn.example.com/lib.js");
      assert.equal(targetA, targetB);
    });

    it("normalizes condition descriptors consistently", () => {
      const condition = normalizeCondition(baseFinding);
      assert.equal(condition, "external third-party scripts include sha384 integrity hashes");
    });
  });

  describe("2. True Duplicate Merging", () => {
    it("identifies true duplicates with identical semantic components", () => {
      const duplicateFinding: Finding = {
        ...baseFinding,
        description: "Another scanner pass reported the same issue.",
      };
      assert.equal(isSemanticDuplicate(baseFinding, duplicateFinding), true);
    });

    it("merges true duplicates while strictly preserving evidence and instances", () => {
      const duplicateFinding: Finding = {
        ...baseFinding,
        evidence: "Secondary probe confirmed: https://cdn.example.com/lib.js is unverified",
        instances: ["https://cdn.example.com/lib.js", "https://cdn.example.com/lib-extra.js"],
        instancesCount: 2,
        structuredEvidence: {
          observation: "Second observation on the same target",
          expectedCondition: baseFinding.structuredEvidence?.expectedCondition,
          metadata: { probeId: "probe-2" },
        },
        limitations: "Target CDN occasionally times out",
      };

      const merged = mergeDuplicateFindings(baseFinding, duplicateFinding);

      // Correlation key preserved
      assert.equal(merged.correlationKey, generateCorrelationKey(baseFinding));

      // Evidence combined
      assert.ok(merged.evidence.includes("Sample script without SRI"));
      assert.ok(merged.evidence.includes("Secondary probe confirmed"));

      // Structured observations combined
      assert.ok(merged.structuredEvidence?.observation.includes("Script tag missing integrity attribute"));
      assert.ok(merged.structuredEvidence?.observation.includes("Second observation on the same target"));

      // Unique instances preserved
      assert.equal(merged.instances?.length, 2);
      assert.ok(merged.instances?.includes("https://cdn.example.com/lib.js"));
      assert.ok(merged.instances?.includes("https://cdn.example.com/lib-extra.js"));
      assert.equal(merged.instancesCount, 2);

      // Metadata merged
      assert.equal((merged.structuredEvidence?.metadata as Record<string, unknown>).probeId, "probe-2");

      // Limitations preserved
      assert.equal(merged.limitations, "Target CDN occasionally times out");
    });
  });

  describe("3. Same Rule / Different Resource Non-Merge", () => {
    it("does NOT merge findings having the same rule ID but different affected targets", () => {
      const findingA: Finding = {
        ...baseFinding,
        affectedTarget: "https://cdn.provider-a.com/script.js",
        instances: ["https://cdn.provider-a.com/script.js"],
      };

      const findingB: Finding = {
        ...baseFinding,
        affectedTarget: "https://cdn.provider-b.com/other-script.js",
        instances: ["https://cdn.provider-b.com/other-script.js"],
      };

      assert.equal(isSemanticDuplicate(findingA, findingB), false);

      const deduplicated = deduplicateFindings([findingA, findingB]);
      assert.equal(deduplicated.length, 2);
      assert.equal(deduplicated[0].affectedTarget, "https://cdn.provider-a.com/script.js");
      assert.equal(deduplicated[1].affectedTarget, "https://cdn.provider-b.com/other-script.js");
    });
  });

  describe("4. Similar Wording / Different Cause Non-Merge", () => {
    it("does NOT merge findings merely because titles or wording resemble each other", () => {
      const missingCspFinding: Finding = {
        id: "sec-csp-missing",
        category: "security",
        severity: "high",
        priority: "critical",
        state: "confirmed",
        confidence: "high",
        title: "Content-Security-Policy (CSP) Header Missing",
        description: "No Content-Security-Policy response header was detected.",
        whyItMatters: "Defense-in-depth against XSS.",
        evidence: 'response.headers["content-security-policy"] is undefined',
        affectedTarget: "HTTP Response Headers",
        recommendation: "Define a strict Content-Security-Policy.",
        structuredEvidence: {
          observation: "CSP undefined",
          expectedCondition: "Content-Security-Policy header defined",
          evidenceType: "header-inspection",
        },
      };

      const unsafeCspFinding: Finding = {
        id: "sec-csp-unsafe",
        category: "security",
        severity: "medium",
        priority: "fix-first",
        state: "confirmed",
        confidence: "high",
        title: "Overly Permissive CSP Directives Detected",
        description: "Permits unsafe-eval or unsafe-inline.",
        whyItMatters: "Permits script injection.",
        evidence: "content-security-policy contains 'unsafe-eval'",
        affectedTarget: "HTTP Response Headers",
        recommendation: "Migrate inline scripts to nonces.",
        structuredEvidence: {
          observation: "CSP permits unsafe-eval",
          expectedCondition: "No un-nonced 'unsafe-inline' or 'unsafe-eval'",
          evidenceType: "header-inspection",
        },
      };

      assert.equal(isSemanticDuplicate(missingCspFinding, unsafeCspFinding), false);

      const deduplicated = deduplicateFindings([missingCspFinding, unsafeCspFinding]);
      assert.equal(deduplicated.length, 2);
      assert.equal(deduplicated[0].id, "sec-csp-missing");
      assert.equal(deduplicated[1].id, "sec-csp-unsafe");
    });
  });

  describe("5. Array Deduplication & Group Correlation", () => {
    it("deduplicates redundant copies within an array and correlates groups", () => {
      const duplicateCopy: Finding = {
        ...baseFinding,
        evidence: "Duplicate check finding identical hash omission",
      };

      const otherFinding: Finding = {
        id: "sec-hsts-missing",
        category: "security",
        severity: "high",
        priority: "fix-first",
        state: "confirmed",
        confidence: "high",
        title: "Strict-Transport-Security (HSTS) Missing",
        description: "HSTS absent.",
        whyItMatters: "SSL-stripping risk.",
        evidence: "HSTS header undefined",
        affectedTarget: "HTTP Response Headers",
        recommendation: "Add HSTS header.",
        structuredEvidence: {
          observation: "HSTS undefined",
          expectedCondition: "Strict-Transport-Security header present",
          evidenceType: "header-inspection",
        },
      };

      const input = [baseFinding, duplicateCopy, otherFinding];
      const result = deduplicateFindings(input);

      assert.equal(result.length, 2);
      assert.equal(result[0].id, "sec-sri-missing");
      assert.equal(result[1].id, "sec-hsts-missing");
      assert.ok(result[0].evidence.includes("Duplicate check finding"));

      const groups = correlateFindings(input);
      assert.equal(groups.size, 2);
      const sriGroup = groups.get(generateCorrelationKey(baseFinding));
      assert.equal(sriGroup?.length, 2);
    });
  });

  describe("6. Live Audit Integration", () => {
    it("ensures live runWebsiteAudit attaches deterministic correlation keys with 0 duplicate collisions", async () => {
      const result = await runWebsiteAudit({ url: "https://example.com", mode: "quick" });

      const seenKeys = new Set<string>();
      for (const finding of result.findings) {
        assert.ok(finding.correlationKey, `Finding ${finding.id} must have a correlationKey`);
        assert.ok(!seenKeys.has(finding.correlationKey), `Duplicate correlationKey found: ${finding.correlationKey}`);
        seenKeys.add(finding.correlationKey);
      }
    });
  });
});
