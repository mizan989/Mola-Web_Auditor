import type { AccessibilityInspection, Finding, PassedCheck } from "../../types/audit.ts";

export interface A11yAuditResult {
  summary: AccessibilityInspection;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Audits accessibility compliance according to WCAG 2.1 AA baselines.
 * Fixed according to ISSUE-020 & ISSUE-021 (strictly verifies accessible names for inputs;
 * an input with only an `id` is properly recognized as unlabelled).
 */
export function auditAccessibility(htmlText: string): A11yAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. Check <html lang="...">
  const htmlTagMatch = htmlText.match(/<html\b[^>]*>/i);
  let hasLang = false;
  let langValue: string | null = null;

  if (htmlTagMatch) {
    const langMatch = htmlTagMatch[0].match(/lang=["']([^"']+)["']/i);
    if (langMatch && langMatch[1].trim()) {
      hasLang = true;
      langValue = langMatch[1].trim();
    }
  }

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
      evidence: htmlTagMatch ? htmlTagMatch[0] : "<html> tag missing lang attribute",
      structuredEvidence: {
        id: "ev-a11y-html-lang-missing",
        affectedTarget: "<html lang>",
        observation: htmlTagMatch ? htmlTagMatch[0] : "<html> tag missing lang attribute",
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
  const allImages = htmlText.match(/<img\b[^>]*>/gi) || [];
  const missingAlt: string[] = [];

  for (const img of allImages) {
    // Check if alt attribute exists at all (even alt="" for decorative images is valid WCAG)
    if (!/\balt\s*=\s*["'][^"']*["']/i.test(img)) {
      missingAlt.push(img.replace(/\s+/g, " ").slice(0, 90));
    }
  }

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
  } else if (allImages.length > 0) {
    passedChecks.push({
      id: "a11y-images-alt-complete",
      category: "accessibility",
      state: "not_detected",
      confidence: "high",
      structuredEvidence: {
        id: "ev-a11y-images-alt-complete",
        affectedTarget: "HTML <img> Elements",
        observation: `All ${allImages.length} images declare alt attributes`,
        expectedCondition: "Zero images missing alt attributes",
        evidenceType: "dom-inspection",
      },
      title: "All Images Have Alt Attributes",
      detail: `All ${allImages.length} images on the page declare alt attributes (informational or decorative).`,
    });
  }

  // 3. Form input accessible labelling (ISSUE-021: id alone is not a label)
  // Collect all IDs referenced by <label for="...">
  const labelForIds = new Set<string>();
  const labelMatches = htmlText.matchAll(/<label\b[^>]*\bfor=["']([^"']+)["'][^>]*>/gi);
  for (const match of labelMatches) {
    if (match[1]) {
      labelForIds.add(match[1].trim());
    }
  }

  // Find all inputs wrapped inside <label>...</label>
  const wrappedInputStrings: string[] = [];
  const wrappingLabelMatches = htmlText.matchAll(/<label\b[^>]*>([\s\S]*?)<\/label>/gi);
  for (const match of wrappingLabelMatches) {
    const inner = match[1];
    const inputsInLabel = inner.match(/<input\b[^>]*>/gi) || [];
    for (const inp of inputsInLabel) {
      wrappedInputStrings.push(inp);
    }
  }

  const formInputs = htmlText.match(/<input\b[^>]*>/gi) || [];
  let unlabelledInputs = 0;
  const unlabelledSamples: string[] = [];

  for (const input of formInputs) {
    const typeMatch = input.match(/\btype=["']([^"']+)["']/i);
    const type = typeMatch ? typeMatch[1].toLowerCase() : "text";
    if (["hidden", "submit", "button", "reset", "image"].includes(type)) continue;

    // Check for explicit ARIA accessible name
    const ariaMatch = input.match(/\baria-label(?:ledby)?=["']([^"']*)["']/i);
    const hasAria = Boolean(ariaMatch && ariaMatch[1].trim());

    // Check for title attribute
    const titleMatch = input.match(/\btitle=["']([^"']*)["']/i);
    const hasTitle = Boolean(titleMatch && titleMatch[1].trim());

    // Check if associated with an external <label for="id">
    const idMatch = input.match(/\bid=["']([^"']+)["']/i);
    const inputId = idMatch ? idMatch[1].trim() : null;
    const hasAssociatedLabelFor = Boolean(inputId && labelForIds.has(inputId));

    // Check if input is nested inside a <label>
    const isWrappedInLabel = wrappedInputStrings.some((w) => w === input);

    const hasAccessibleName = hasAria || hasTitle || hasAssociatedLabelFor || isWrappedInLabel;

    if (!hasAccessibleName) {
      unlabelledInputs++;
      if (unlabelledSamples.length < 5) {
        unlabelledSamples.push(input.replace(/\s+/g, " ").slice(0, 90));
      }
    }
  }

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
  } else if (formInputs.length > 0) {
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

  // 4. Landmarks: <main>, <header>, <nav>
  const hasMain = /<main\b/i.test(htmlText) || /role=["']main["']/i.test(htmlText);
  const hasHeader = /<header\b/i.test(htmlText) || /role=["']banner["']/i.test(htmlText);

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
    imagesTotal: allImages.length,
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
