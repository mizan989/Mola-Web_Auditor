import type { AccessibilityInspection, AuditContext, Finding, PassedCheck } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import {
  parseHtmlDocument,
  extractHtmlLanguage,
  extractImageAccessibility,
  extractFormLabels,
  extractLandmarks,
} from "../htmlParser.ts";

export interface A11yAuditResult {
  summary: AccessibilityInspection;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Audits accessibility compliance according to WCAG 2.1 AA baselines.
 * Consumes the shared authoritative AuditContext (Phase 2), with fallback to raw HTML string.
 * Uses structured HTML parsing (Phase 4) to evaluate language attributes, image alternatives,
 * form labelling (including nested labels and explicit for attributes), duplicate IDs, and landmarks.
 */
export function auditAccessibility(contextOrHtml: AuditContext | string): A11yAuditResult {
  const isCtx = isAuditContext(contextOrHtml);
  const htmlText = isCtx ? contextOrHtml.body.text : (contextOrHtml as string);

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const root = parseHtmlDocument(htmlText);

  // 1. Check <html lang="...">
  const { hasLang, lang: langValue, rawTag } = extractHtmlLanguage(root);

  if (!hasLang || !langValue) {
    findings.push({
      id: "a11y-html-lang-missing",
      category: "accessibility",
      severity: "high",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Document Language (lang) Attribute Missing",
      description: "The root <html> element does not specify a valid 'lang' attribute.",
      whyItMatters:
        "Screen readers rely on the lang attribute to invoke correct text-to-speech pronunciation rules, accent models, and dictionary translation.",
      evidence: rawTag || "<html> tag missing lang attribute",
      structuredEvidence: {
        id: "ev-a11y-html-lang-missing",
        affectedTarget: "<html lang>",
        observation: rawTag || "<html> tag missing lang attribute",
        expectedCondition: "Valid BCP 47 language code on <html> element",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "<html lang>",
      recommendation: "Add a valid BCP 47 language code (such as 'en' or 'en-US') to the <html> opening tag.",
      codeSnippet: '<html lang="en">',
    });
  } else {
    passedChecks.push({
      id: "a11y-html-lang-valid",
      category: "accessibility",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-a11y-html-lang-valid",
        affectedTarget: "<html lang>",
        observation: `Root document language declared as '${langValue}'`,
        expectedCondition: "Valid lang attribute present",
        evidenceType: "dom-inspection",
      },
      title: "Valid HTML Language Attribute",
      detail: `Root document language declared as '${langValue}'.`,
    });
  }

  // 2. Image alt attributes
  const { totalImages, missingAlt } = extractImageAccessibility(root);

  if (missingAlt.length > 0) {
    findings.push({
      id: "a11y-images-missing-alt",
      category: "accessibility",
      severity: "high",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Images Missing Descriptive Alt Text",
      description: `Detected ${missingAlt.length} image(s) lacking an 'alt' attribute.`,
      whyItMatters:
        "Screen reader users cannot perceive images without alternative text; assistive technology will often read the raw filename URL instead.",
      evidence: `Sample element: ${missingAlt[0] || ""}`,
      structuredEvidence: {
        id: "ev-a11y-images-missing-alt",
        affectedTarget: "HTML <img> Elements",
        observation: `${missingAlt.length} <img> tags lack alt attribute`,
        expectedCondition: "All <img> elements declare an alt attribute",
        evidenceType: "dom-inspection",
        metadata: { missingCount: missingAlt.length },
      },
      affectedTarget: "HTML <img> Elements",
      recommendation:
        "Provide meaningful alt descriptions for informational images, or alt=\"\" for purely decorative graphics.",
      codeSnippet: '<img src="/illustration.png" alt="Audit telemetry report preview" />',
      instancesCount: missingAlt.length,
      instances: missingAlt.slice(0, 5),
    });
  } else if (totalImages > 0) {
    passedChecks.push({
      id: "a11y-images-alt-complete",
      category: "accessibility",
      state: "not_detected",
      confidence: "high",
      structuredEvidence: {
        id: "ev-a11y-images-alt-complete",
        affectedTarget: "HTML <img> Elements",
        observation: `All ${totalImages} images declare alt attributes`,
        expectedCondition: "Zero images missing alt attributes",
        evidenceType: "dom-inspection",
      },
      title: "All Images Have Alt Attributes",
      detail: `All ${totalImages} images on the page declare alt attributes (informational or decorative).`,
    });
  }

  // 3. Form input accessible labelling & Duplicate IDs (ISSUE-021)
  const { totalInputs, unlabelledInputs, unlabelledSamples, duplicateIds } = extractFormLabels(root);

  if (unlabelledInputs > 0) {
    findings.push({
      id: "a11y-inputs-unlabelled",
      category: "accessibility",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Form Inputs Missing Accessible Labels",
      description: `${unlabelledInputs} interactive input field(s) lack an accessible name (no associated <label for>, wrapping <label>, aria-label, or title).`,
      whyItMatters:
        "Unlabelled form fields leave screen reader users unable to know what input data is expected. An 'id' attribute alone does not provide an accessible name.",
      evidence: `Sample unlabelled input: ${unlabelledSamples[0] || `Found ${unlabelledInputs} unlabelled inputs`}`,
      structuredEvidence: {
        id: "ev-a11y-inputs-unlabelled",
        affectedTarget: "<input> Form Controls",
        observation: `${unlabelledInputs} form inputs lack accessible names`,
        expectedCondition: "All interactive inputs have an accessible name",
        evidenceType: "dom-inspection",
        metadata: { unlabelledCount: unlabelledInputs },
      },
      affectedTarget: "<input> Form Controls",
      recommendation:
        "Associate an explicit <label for=\"...\"> with each input, wrap the input inside a <label>, or provide an aria-label attribute.",
      codeSnippet: '<label for="email-field">Email address</label>\n<input id="email-field" type="email" />',
      instancesCount: unlabelledInputs,
      instances: unlabelledSamples,
    });
  } else if (totalInputs > 0) {
    passedChecks.push({
      id: "a11y-inputs-labelled",
      category: "accessibility",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-a11y-inputs-labelled",
        affectedTarget: "<input> Form Controls",
        observation: "All inputs have verifiable accessible names",
        expectedCondition: "Form inputs labelled",
        evidenceType: "dom-inspection",
      },
      title: "All Form Inputs Have Accessible Labels",
      detail: "Interactive form controls have verifiable accessible names via labels or ARIA attributes.",
    });
  }

  // Duplicate ID detection (WCAG 4.1.1)
  if (duplicateIds.length > 0) {
    findings.push({
      id: "a11y-duplicate-ids",
      category: "accessibility",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Duplicate HTML Element IDs Detected",
      description: `Detected ${duplicateIds.length} duplicate 'id' attribute values (${duplicateIds.slice(0, 3).join(", ")}).`,
      whyItMatters:
        "Duplicate IDs break form label associations, anchor links, and assistive technology navigation that relies on unique element identifiers.",
      evidence: `Duplicate IDs: ${duplicateIds.join(", ")}`,
      structuredEvidence: {
        id: "ev-a11y-duplicate-ids",
        affectedTarget: "Document DOM",
        observation: `Detected ${duplicateIds.length} duplicate element IDs: ${duplicateIds.join(", ")}`,
        expectedCondition: "All element ID attributes are unique across document",
        evidenceType: "dom-inspection",
        metadata: { duplicateIds, count: duplicateIds.length },
      },
      affectedTarget: "Document DOM",
      recommendation: "Ensure all 'id' attribute values are strictly unique within the HTML document.",
      instancesCount: duplicateIds.length,
      instances: duplicateIds,
    });
  }

  // 4. Landmarks: <main>, <header>, <nav>
  const { hasMain, hasHeader } = extractLandmarks(root);

  if (!hasMain) {
    findings.push({
      id: "a11y-main-landmark-missing",
      category: "accessibility",
      severity: "low",
      priority: "recommended",
      state: "recommendation",
      confidence: "high",
      title: "Document Missing <main> Landmark",
      description: "No <main> landmark element was found wrapping primary content.",
      whyItMatters:
        "Landmark elements allow screen reader and keyboard users to jump directly to primary content, bypassing repeated navigation headers.",
      evidence: '<main> or role="main" → not found in document',
      structuredEvidence: {
        id: "ev-a11y-main-landmark-missing",
        affectedTarget: "Page Layout",
        observation: '<main> landmark not found in document',
        expectedCondition: "Primary content wrapped in <main> landmark",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "Page Layout",
      recommendation: "Wrap primary body content inside a <main> semantic container.",
      codeSnippet: '<main id="main-content">\n  <!-- Primary content -->\n</main>',
    });
  } else {
    passedChecks.push({
      id: "a11y-main-landmark-present",
      category: "accessibility",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-a11y-main-landmark-present",
        affectedTarget: "Page Layout",
        observation: "Semantic <main> landmark element detected",
        expectedCondition: "<main> landmark present",
        evidenceType: "dom-inspection",
      },
      title: "Semantic <main> Landmark Present",
      detail: "Page utilizes semantic landmark navigation.",
    });
  }

  const summary: AccessibilityInspection = {
    imagesTotal: totalImages,
    imagesMissingAlt: missingAlt.length,
    missingAltElements: missingAlt.slice(0, 5),
    hasLang,
    lang: langValue,
    hasMainLandmark: hasMain,
    hasHeaderLandmark: hasHeader,
    inputsMissingLabel: unlabelledInputs,
  };

  return { summary, findings, passedChecks };
}
