import { Finding, PassedCheck } from "@/types/audit";

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
      title: "Modern HTML5 DOCTYPE Declaration Missing",
      description: "Document lacks the standard <!DOCTYPE html> declaration at the beginning.",
      whyItMatters:
        "Omitting DOCTYPE triggers browser quirks mode, causing subtle layout anomalies, outdated box-sizing, and unpredictable CSS rendering across browsers.",
      evidence: "First characters do not contain <!DOCTYPE html>",
      affectedTarget: "Document Root",
      recommendation: "Prepend `<!DOCTYPE html>` as the very first line of your HTML document.",
      codeSnippet: "<!DOCTYPE html>\n<html lang=\"en\">",
    });
  } else {
    passedChecks.push({
      id: "bp-doctype-present",
      category: "best-practices",
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
      title: "Explicit UTF-8 Character Encoding Missing",
      description: "No `<meta charset=\"utf-8\">` was detected within the `<head>`.",
      whyItMatters:
        "Without an early charset declaration, browsers must guess the byte encoding, potentially corrupting special characters or emojis.",
      evidence: '<meta charset="utf-8"> → not found',
      affectedTarget: "<head> Meta",
      recommendation: "Place `<meta charset=\"utf-8\">` as the first child of the `<head>` block.",
      codeSnippet: '<meta charset="utf-8">',
    });
  } else {
    passedChecks.push({
      id: "bp-charset-present",
      category: "best-practices",
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
      title: "Deprecated HTML Tags Detected",
      description: `Detected deprecated HTML tags (${foundDeprecated.join(", ")}).`,
      whyItMatters:
        "Deprecated tags have been dropped from modern HTML specifications and can cause inconsistent rendering or accessibility bugs.",
      evidence: `Found deprecated tags: ${foundDeprecated.join(", ")}`,
      affectedTarget: "HTML Body Elements",
      recommendation: "Replace deprecated tags with modern CSS styling (Flexbox/Grid for centering, modern fonts, animations).",
    });
  } else {
    passedChecks.push({
      id: "bp-clean-markup",
      category: "best-practices",
      title: "Modern HTML Markup",
      detail: "No deprecated HTML tags detected in document.",
    });
  }

  return { findings, passedChecks };
}
