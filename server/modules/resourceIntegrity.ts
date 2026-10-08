import type { AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import { parseHtmlDocument, extractScripts } from "../htmlParser.ts";
import { validateSriCandidate } from "../candidateValidator.ts";

export interface ResourceIntegrityAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Specialized Audit Module: Resource Integrity (SRI) (Phase 8).
 * Inspects external third-party script assets to verify cryptographic SRI hashes.
 */
export function auditResourceIntegrity(
  contextOrOptions: AuditContext | { finalUrl: string; htmlText: string },
  legacyHtmlText?: string
): ResourceIntegrityAuditResult {
  let finalUrl: string;
  let htmlText: string;

  if (isAuditContext(contextOrOptions)) {
    finalUrl = contextOrOptions.finalUrl;
    htmlText = contextOrOptions.body.text;
  } else if (typeof contextOrOptions === "object" && "htmlText" in contextOrOptions) {
    finalUrl = contextOrOptions.finalUrl;
    htmlText = contextOrOptions.htmlText;
  } else {
    finalUrl = typeof contextOrOptions === "string" ? contextOrOptions : "";
    htmlText = legacyHtmlText || "";
  }

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  let host: string;
  try {
    host = new URL(finalUrl).hostname;
  } catch {
    host = "";
  }

  const root = parseHtmlDocument(htmlText);
  const scripts = extractScripts(root);
  const externalScriptsWithoutSri: string[] = [];
  let totalExternalScripts = 0;

  for (const script of scripts) {
    const evaluation = validateSriCandidate({
      src: script.src,
      host,
      finalUrl,
      hasIntegrity: script.hasIntegrity,
    });

    if (evaluation.outcome === "confirmed") {
      externalScriptsWithoutSri.push(script.src);
      totalExternalScripts++;
    } else if (
      evaluation.outcome === "rejected" &&
      (script.src.startsWith("//") || script.src.startsWith("http://") || script.src.startsWith("https://"))
    ) {
      try {
        if (new URL(script.src, finalUrl).hostname !== host) {
          totalExternalScripts++;
        }
      } catch {
        // Ignore unparseable URLs
      }
    }
  }

  if (externalScriptsWithoutSri.length > 0) {
    findings.push({
      id: "sec-sri-missing",
      category: "security",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Third-Party Scripts Missing Subresource Integrity (SRI)",
      description: `Detected ${externalScriptsWithoutSri.length} external script(s) loaded from third-party domains without cryptographic 'integrity' hashes.`,
      whyItMatters:
        "If a third-party CDN or external host is compromised, adversaries can tamper with script assets and execute malicious code in your users' browsers without SRI verification.",
      evidence: `Sample external script without SRI: ${externalScriptsWithoutSri[0]}`,
      structuredEvidence: {
        id: "ev-sec-sri-missing",
        sourceUrl: finalUrl,
        affectedTarget: externalScriptsWithoutSri[0],
        observation: `Detected ${externalScriptsWithoutSri.length} external script(s) loaded from third-party domains without cryptographic integrity hashes.`,
        expectedCondition: "External third-party scripts include sha384 or sha512 integrity hashes and crossorigin='anonymous'",
        evidenceType: "html-script-inspection",
        metadata: {
          count: externalScriptsWithoutSri.length,
          instances: externalScriptsWithoutSri.slice(0, 5),
        },
        limitations: "Static HTML analysis; dynamically loaded scripts cannot be evaluated without headless browser execution.",
      },
      affectedTarget: "<script> tags",
      recommendation:
        "Add cryptographic sha384 or sha512 integrity hashes and crossorigin=\"anonymous\" attributes to all external scripts.",
      codeSnippet:
        '<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-..."\n  crossorigin="anonymous"></script>',
      instancesCount: externalScriptsWithoutSri.length,
      instances: externalScriptsWithoutSri.slice(0, 5),
      limitations: "Static HTML analysis; dynamically loaded scripts cannot be evaluated without headless browser execution.",
    });
  } else if (totalExternalScripts > 0) {
    passedChecks.push({
      id: "sec-sri-verified",
      category: "security",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-sec-sri-verified",
        sourceUrl: finalUrl,
        affectedTarget: "<script> tags",
        observation: `All ${totalExternalScripts} external third-party scripts include cryptographic integrity hashes.`,
        expectedCondition: "External scripts enforce SRI hashes",
        evidenceType: "html-script-inspection",
      },
      title: "Subresource Integrity (SRI) Enforced",
      detail: `All ${totalExternalScripts} external third-party scripts include cryptographic integrity hashes.`,
    });
  }

  return { findings, passedChecks };
}
