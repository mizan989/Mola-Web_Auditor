import type { Finding, PassedCheck } from "../../types/audit.ts";

export interface BestPracticesAuditResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
}

export function auditBestPractices(htmlText: string): BestPracticesAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. HTML5 Doctype Check
  const hasDoctype = /<!doctype\s+html\b/i.test(htmlText);
  if (!hasDoctype) {
    findings.push({
      id: "bp-doctype-missing",
      category: "best-practices",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Modern HTML5 DOCTYPE Declaration Missing",
      description: "Document lacks the standard <!DOCTYPE html> declaration at the beginning.",
      whyItMatters:
        "Omitting DOCTYPE triggers browser quirks mode, causing subtle layout anomalies, outdated box-sizing, and unpredictable CSS rendering across browsers.",
      evidence: "First characters do not contain <!DOCTYPE html>",
      structuredEvidence: {
        id: "ev-bp-doctype-missing",
        affectedTarget: "Document Root",
        observation: "Missing <!DOCTYPE html> declaration",
        expectedCondition: "<!DOCTYPE html> at start of document",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "Document Root",
      recommendation: "Prepend `<!DOCTYPE html>` as the very first line of your HTML document.",
      codeSnippet: "<!DOCTYPE html>\n<html lang=\"en\">",
    });
  } else {
    passedChecks.push({
      id: "bp-doctype-present",
      category: "best-practices",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-bp-doctype-present",
        affectedTarget: "Document Root",
        observation: "<!DOCTYPE html> detected",
        expectedCondition: "<!DOCTYPE html> declared",
        evidenceType: "dom-inspection",
      },
      title: "HTML5 Standards DOCTYPE Present",
      detail: "Document triggers standard rendering mode.",
    });
  }

  // 2. Character Set UTF-8
  const hasCharset = /<meta\b[^>]*charset=["']?utf-8["']?/i.test(htmlText) ||
    /http-equiv=["']content-type["'][^>]*content=["'][^"']*charset=utf-8/i.test(htmlText);

  if (!hasCharset) {
    findings.push({
      id: "bp-charset-missing",
      category: "best-practices",
      severity: "low",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Explicit UTF-8 Character Encoding Missing",
      description: "No `<meta charset=\"utf-8\">` was detected within the `<head>`.",
      whyItMatters:
        "Without an early charset declaration, browsers must guess the byte encoding, potentially corrupting special characters or emojis.",
      evidence: '<meta charset="utf-8"> → not found',
      structuredEvidence: {
        id: "ev-bp-charset-missing",
        affectedTarget: "<head> Meta",
        observation: '<meta charset="utf-8"> not found',
        expectedCondition: "UTF-8 charset declaration present",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "<head> Meta",
      recommendation: "Place `<meta charset=\"utf-8\">` as the first child of the `<head>` block.",
      codeSnippet: '<meta charset="utf-8">',
    });
  } else {
    passedChecks.push({
      id: "bp-charset-present",
      category: "best-practices",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-bp-charset-present",
        affectedTarget: "<head> Meta",
        observation: "UTF-8 character encoding specified",
        expectedCondition: "UTF-8 charset declared",
        evidenceType: "dom-inspection",
      },
      title: "UTF-8 Charset Declared",
      detail: "Valid UTF-8 character encoding specified.",
    });
  }

  // 3. Obsolete / Deprecated HTML tags
  const deprecatedTags = ["center", "font", "marquee", "blink", "frame", "frameset", "applet", "strike"];
  const foundDeprecated: string[] = [];

  for (const tag of deprecatedTags) {
    const regex = new RegExp(`<${tag}\\b`, "i");
    if (regex.test(htmlText)) {
      foundDeprecated.push(`<${tag}>`);
    }
  }

  if (foundDeprecated.length > 0) {
    findings.push({
      id: "bp-deprecated-tags",
      category: "best-practices",
      severity: "low",
      priority: "investigate",
      state: "confirmed",
      confidence: "high",
      title: "Deprecated HTML Tags Detected",
      description: `Detected deprecated HTML tags (${foundDeprecated.join(", ")}).`,
      whyItMatters:
        "Deprecated tags have been dropped from modern HTML specifications and can cause inconsistent rendering or accessibility bugs.",
      evidence: `Found deprecated tags: ${foundDeprecated.join(", ")}`,
      structuredEvidence: {
        id: "ev-bp-deprecated-tags",
        affectedTarget: "HTML Body Elements",
        observation: `Found deprecated tags: ${foundDeprecated.join(", ")}`,
        expectedCondition: "Zero deprecated HTML elements",
        evidenceType: "dom-inspection",
        metadata: { foundDeprecated },
      },
      affectedTarget: "HTML Body Elements",
      recommendation: "Replace deprecated tags with modern CSS styling (Flexbox/Grid for centering, modern fonts, animations).",
    });
  } else {
    passedChecks.push({
      id: "bp-clean-markup",
      category: "best-practices",
      state: "not_detected",
      confidence: "high",
      structuredEvidence: {
        id: "ev-bp-clean-markup",
        affectedTarget: "HTML Body Elements",
        observation: "Zero deprecated HTML elements detected",
        expectedCondition: "Zero deprecated tags",
        evidenceType: "dom-inspection",
      },
      title: "Modern HTML Markup",
      detail: "No deprecated HTML tags detected in document.",
    });
  }

  return { findings, passedChecks };
}
