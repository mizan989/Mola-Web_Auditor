import { AccessibilityInspection, Finding, PassedCheck } from "@/types/audit";

export interface A11yAuditResult {
  summary: AccessibilityInspection;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

export function auditAccessibility(htmlText: string): A11yAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. Check <html lang="...">
  const htmlTagMatch = htmlText.match(/<html\b[^>]*>/i);
  let hasLang = false;
  let langValue: string | null = null;

  if (htmlTagMatch) {
    const langMatch = htmlTagMatch[0].match(/lang=["']([^"']+)["']/i);
    if (langMatch) {
      hasLang = true;
      langValue = langMatch[1];
    }
  }

  if (!hasLang || !langValue) {
    findings.push({
      id: "a11y-html-lang-missing",
      category: "accessibility",
      severity: "high",
      priority: "fix-first",
      title: "Document Language (lang) Attribute Missing",
      description: "The root <html> element does not specify a valid 'lang' attribute.",
      whyItMatters:
        "Screen readers rely on the lang attribute to invoke correct text-to-speech pronunciation rules, accent models, and dictionary translation.",
      evidence: htmlTagMatch ? htmlTagMatch[0] : "<html> tag missing lang",
      affectedTarget: "<html lang>",
      recommendation: "Add a valid BCP 47 language code (such as 'en' or 'en-US') to the <html> opening tag.",
      codeSnippet: '<html lang="en">',
    });
  } else {
    passedChecks.push({
      id: "a11y-html-lang-valid",
      category: "accessibility",
      title: "Valid HTML Language Attribute",
      detail: `Root document language declared as '${langValue}'.`,
    });
  }

  // 2. Image alt attributes
  const allImages = htmlText.match(/<img\b[^>]*>/gi) || [];
  const missingAlt: string[] = [];

  for (const img of allImages) {
    if (!/alt=["'][^"']*["']/i.test(img)) {
      missingAlt.push(img.replace(/\s+/g, " ").slice(0, 90));
    }
  }

  if (missingAlt.length > 0) {
    findings.push({
      id: "a11y-images-missing-alt",
      category: "accessibility",
      severity: "high",
      priority: "fix-first",
      title: "Images Missing Descriptive Alt Text",
      description: `Detected ${missingAlt.length} image(s) lacking an 'alt' attribute.`,
      whyItMatters:
        "Screen reader users cannot perceive images without alternative text; assistive technology will often read the raw filename URL instead.",
      evidence: `Sample element: ${missingAlt[0] || ""}`,
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
      title: "All Images Have Alt Attributes",
      detail: `All ${allImages.length} images on the page declare alt attributes.`,
    });
  }

  // 3. Form input labeling
  const formInputs = htmlText.match(/<input\b[^>]*>/gi) || [];
  let unlabelledInputs = 0;
  for (const input of formInputs) {
    const typeMatch = input.match(/type=["']([^"']+)["']/i);
    const type = typeMatch ? typeMatch[1].toLowerCase() : "text";
    if (["hidden", "submit", "button", "reset"].includes(type)) continue;

    const hasAriaLabel = /aria-label(?:ledby)?=["'][^"']+["']/i.test(input);
    const hasId = /id=["']([^"']+)["']/i.test(input);
    const hasTitle = /title=["']([^"']+)["']/i.test(input);

    if (!hasAriaLabel && !hasTitle && !hasId) {
      unlabelledInputs++;
    }
  }

  if (unlabelledInputs > 0) {
    findings.push({
      id: "a11y-inputs-unlabelled",
      category: "accessibility",
      severity: "medium",
      priority: "recommended",
      title: "Form Inputs Missing Accessible Labels",
      description: `${unlabelledInputs} input field(s) lack an associated <label>, aria-label, or title.`,
      whyItMatters:
        "Unlabelled form fields leave blind and low-vision users unable to identify what input data is expected.",
      evidence: `Found ${unlabelledInputs} interactive inputs without accessible labels`,
      affectedTarget: "<input> Form Controls",
      recommendation:
        "Associate an explicit <label for=\"...\"> with each input, or provide an aria-label attribute.",
      codeSnippet: '<label for="search">Search</label>\n<input id="search" type="text" />',
      instancesCount: unlabelledInputs,
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
      title: "Document Missing <main> Landmark",
      description: "No <main> landmark element was found wrapping primary content.",
      whyItMatters:
        "Landmark elements allow screen reader and keyboard users to jump directly to primary content, bypassing repeated navigation headers.",
      evidence: '<main> or role="main" → not found',
      affectedTarget: "Page Layout",
      recommendation: "Wrap primary body content inside a <main> semantic container.",
      codeSnippet: "<main id=\"main-content\">\n  <!-- Primary content -->\n</main>",
    });
  } else {
    passedChecks.push({
      id: "a11y-main-landmark-present",
      category: "accessibility",
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
