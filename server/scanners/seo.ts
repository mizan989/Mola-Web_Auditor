import type { AuditContext, Finding, PassedCheck, SeoInspection } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";
import {
  parseHtmlDocument,
  extractDocumentTitle,
  extractMetaDescription,
  extractCanonicalLinks,
  extractViewportMeta,
  extractOpenGraphMeta,
  extractRobotsMeta,
  extractHeadings,
} from "../htmlParser.ts";

export interface SeoAuditResult {
  seoData: SeoInspection;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Audits technical search engine optimization (SEO) factors.
 * Consumes the shared authoritative AuditContext (Phase 2), with fallback to raw HTML string.
 * Uses structured HTML parsing to accurately inspect titles, metas, canonicals, and heading hierarchies (Phase 4).
 */
export function auditSeo(contextOrHtml: AuditContext | string): SeoAuditResult {
  const isCtx = isAuditContext(contextOrHtml);
  const htmlText = isCtx ? contextOrHtml.body.text : (contextOrHtml as string);

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const root = parseHtmlDocument(htmlText);

  // 1. Document <title>
  const { rawTitle } = extractDocumentTitle(root);
  const titleLength = rawTitle ? rawTitle.length : 0;

  if (!rawTitle) {
    findings.push({
      id: "seo-title-missing",
      category: "seo",
      severity: "high",
      priority: "critical",
      state: "confirmed",
      confidence: "high",
      title: "Document <title> Tag Missing",
      description: "The HTML document has no <title> tag inside the <head> element.",
      whyItMatters:
        "The <title> tag is the primary textual signal for search engine ranking algorithms and is displayed as the clickable headline in search snippets and browser tabs.",
      evidence: "<head> contains no <title>...</title> element",
      structuredEvidence: {
        id: "ev-seo-title-missing",
        affectedTarget: "<head> Element",
        observation: "<title> element is absent in document head",
        expectedCondition: "Document contains a descriptive <title> element",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "<head> Element",
      recommendation: "Provide a unique, descriptive <title> tag between 30 and 65 characters.",
      codeSnippet: "<title>Primary Keyword — Brand Name</title>",
    });
  } else if (titleLength < 15) {
    findings.push({
      id: "seo-title-short",
      category: "seo",
      severity: "low",
      priority: "recommended",
      state: "recommendation",
      confidence: "high",
      title: "Document <title> Is Too Brief",
      description: `The page title is only ${titleLength} characters long ("${rawTitle}").`,
      whyItMatters:
        "Extremely short page titles miss the opportunity to convey relevant keywords, brand clarity, and context to search engines.",
      evidence: `<title>${rawTitle}</title> (Observed length: ${titleLength} chars)`,
      structuredEvidence: {
        id: "ev-seo-title-short",
        affectedTarget: "<title>",
        observation: `Title text is ${titleLength} characters: "${rawTitle}"`,
        expectedCondition: "Title between 30 and 65 characters",
        evidenceType: "dom-inspection",
        metadata: { titleLength, rawTitle },
      },
      affectedTarget: "<title>",
      recommendation: "Expand the title to 30–65 characters including primary product or topic keywords.",
    });
  } else if (titleLength > 70) {
    findings.push({
      id: "seo-title-long",
      category: "seo",
      severity: "low",
      priority: "recommended",
      state: "recommendation",
      confidence: "high",
      title: "Document <title> May Be Truncated in SERP",
      description: `The page title is ${titleLength} characters long (exceeds typical 60–70 character desktop limit).`,
      whyItMatters:
        "Search engines automatically truncate excessively long titles in search engine results pages with an ellipsis ('…').",
      evidence: `<title>${rawTitle.slice(0, 65)}...</title> (Observed length: ${titleLength} chars)`,
      structuredEvidence: {
        id: "ev-seo-title-long",
        affectedTarget: "<title>",
        observation: `Title length is ${titleLength} characters`,
        expectedCondition: "Title length under 70 characters",
        evidenceType: "dom-inspection",
        metadata: { titleLength },
      },
      affectedTarget: "<title>",
      recommendation: "Trim the title to under 65 characters to avoid awkward search snippet truncation.",
    });
  } else {
    passedChecks.push({
      id: "seo-title-valid",
      category: "seo",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-seo-title-valid",
        affectedTarget: "<title>",
        observation: `Title "${rawTitle}" is ${titleLength} characters`,
        expectedCondition: "Title length in optimal 15-70 range",
        evidenceType: "dom-inspection",
      },
      title: "Optimal Title Length",
      detail: `Title "${rawTitle}" is ${titleLength} characters (within recommended 15–70 range).`,
    });
  }

  // 2. Extract <meta name="description">
  const { metaDesc } = extractMetaDescription(root);
  const descLength = metaDesc ? metaDesc.length : 0;

  if (!metaDesc) {
    findings.push({
      id: "seo-meta-description-missing",
      category: "seo",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Meta Description Tag Missing",
      description: "No <meta name=\"description\"> tag was found on the page.",
      whyItMatters:
        "Search engines display this snippet below your page title. A compelling description directly influences organic Click-Through-Rate (CTR).",
      evidence: '<meta name="description"> not found in <head>',
      structuredEvidence: {
        id: "ev-seo-meta-description-missing",
        affectedTarget: "<head> Meta Elements",
        observation: '<meta name="description"> absent',
        expectedCondition: "Descriptive meta description in 120-160 characters",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "<head> Meta Elements",
      recommendation:
        "Add a concise meta description summarizing the page content in 120–160 characters.",
      codeSnippet: '<meta name="description" content="Accurate summary of website offering...">',
    });
  } else if (descLength < 50) {
    findings.push({
      id: "seo-meta-description-short",
      category: "seo",
      severity: "low",
      priority: "recommended",
      state: "recommendation",
      confidence: "high",
      title: "Meta Description Is Abnormally Short",
      description: `The meta description contains only ${descLength} characters.`,
      whyItMatters:
        "Short descriptions may cause search engines to substitute arbitrary body text in search results instead of your intended copy.",
      evidence: `content="${metaDesc}" (Observed length: ${descLength} chars)`,
      structuredEvidence: {
        id: "ev-seo-meta-description-short",
        affectedTarget: '<meta name="description">',
        observation: `Description content is ${descLength} characters: "${metaDesc}"`,
        expectedCondition: "Meta description length between 120 and 160 characters",
        evidenceType: "dom-inspection",
        metadata: { descLength },
      },
      affectedTarget: '<meta name="description">',
      recommendation: "Flesh out the meta description to between 120 and 160 characters.",
    });
  } else {
    passedChecks.push({
      id: "seo-meta-description-valid",
      category: "seo",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-seo-meta-description-valid",
        affectedTarget: '<meta name="description">',
        observation: `Meta description contains ${descLength} characters`,
        expectedCondition: "Meta description present with sufficient length",
        evidenceType: "dom-inspection",
      },
      title: "Meta Description Present",
      detail: `Meta description contains ${descLength} characters.`,
    });
  }

  // 3. Canonical URL
  const { canonicalUrl, canonicals } = extractCanonicalLinks(root);

  if (canonicals.length > 1) {
    findings.push({
      id: "seo-canonical-multiple",
      category: "seo",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Multiple Canonical Link Tags Detected",
      description: `Detected ${canonicals.length} conflicting <link rel="canonical"> tags in document.`,
      whyItMatters:
        "When multiple canonical tags exist, search engines may disregard all of them or pick an arbitrary one, disrupting search indexing.",
      evidence: `Found ${canonicals.length} canonical links: ${canonicals.join(", ")}`,
      structuredEvidence: {
        id: "ev-seo-canonical-multiple",
        affectedTarget: "<head> Links",
        observation: `Detected ${canonicals.length} conflicting canonical link tags`,
        expectedCondition: "Exactly one canonical link tag",
        evidenceType: "dom-inspection",
        metadata: { canonicals, count: canonicals.length },
      },
      affectedTarget: "<head> Links",
      recommendation: "Ensure only one self-referential <link rel=\"canonical\"> tag is declared.",
      instancesCount: canonicals.length,
      instances: canonicals,
    });
  }

  if (!canonicalUrl) {
    findings.push({
      id: "seo-canonical-missing",
      category: "seo",
      severity: "medium",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Canonical Link Tag Missing",
      description: "No <link rel=\"canonical\"> tag was found in the page header.",
      whyItMatters:
        "Without a canonical URL, search engines can split link equity across URL variations (e.g. http vs https, trailing slashes, tracking query parameters).",
      evidence: '<link rel="canonical" ...> not found in <head>',
      structuredEvidence: {
        id: "ev-seo-canonical-missing",
        affectedTarget: "<head> Links",
        observation: '<link rel="canonical"> tag not detected in document',
        expectedCondition: "Explicit self-referential canonical URL tag",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "<head> Links",
      recommendation: "Declare a self-referential canonical URL tag.",
      codeSnippet: '<link rel="canonical" href="https://example.com/page" />',
    });
  } else if (canonicals.length === 1) {
    passedChecks.push({
      id: "seo-canonical-present",
      category: "seo",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-seo-canonical-present",
        affectedTarget: "<head> Links",
        observation: `Canonical points to ${canonicalUrl}`,
        expectedCondition: "Canonical link present",
        evidenceType: "dom-inspection",
      },
      title: "Canonical Link Declared",
      detail: `Canonical points to ${canonicalUrl}`,
    });
  }

  // 4. Mobile Viewport Meta Tag
  const viewportContent = extractViewportMeta(root);
  if (!viewportContent) {
    findings.push({
      id: "seo-viewport-missing",
      category: "seo",
      severity: "high",
      priority: "critical",
      state: "confirmed",
      confidence: "high",
      title: "Mobile Responsive Viewport Meta Tag Missing",
      description: "The document does not define a standard mobile viewport tag.",
      whyItMatters:
        "Mobile browsers will render the page at desktop widths and scale down, destroying mobile legibility and severely harming Google Mobile-First indexing.",
      evidence: '<meta name="viewport" ...> not found in document',
      structuredEvidence: {
        id: "ev-seo-viewport-missing",
        affectedTarget: "<head>",
        observation: '<meta name="viewport"> tag absent',
        expectedCondition: "Responsive viewport meta tag declared",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "<head>",
      recommendation: "Include the standard responsive viewport meta tag.",
      codeSnippet: '<meta name="viewport" content="width=device-width, initial-scale=1.0" />',
    });
  } else {
    passedChecks.push({
      id: "seo-viewport-present",
      category: "seo",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-seo-viewport-present",
        affectedTarget: "<head>",
        observation: `Viewport: ${viewportContent}`,
        expectedCondition: "Responsive viewport meta tag configured",
        evidenceType: "dom-inspection",
      },
      title: "Responsive Viewport Configured",
      detail: `Viewport: ${viewportContent}`,
    });
  }

  // 5. OpenGraph & Social Sharing Meta Tags
  const { ogTitle, ogImage } = extractOpenGraphMeta(root);

  if (!ogTitle || !ogImage) {
    findings.push({
      id: "seo-opengraph-incomplete",
      category: "seo",
      severity: "low",
      priority: "recommended",
      state: "recommendation",
      confidence: "high",
      title: "Social Sharing OpenGraph Tags Incomplete",
      description: `Missing essential social preview metadata (${!ogTitle ? "og:title " : ""}${!ogImage ? "og:image" : ""}).`,
      whyItMatters:
        "When your link is shared on Slack, Discord, Twitter/X, or LinkedIn, it will fail to render a rich link preview card with thumbnail imagery.",
      evidence: `og:title: ${ogTitle ? `"${ogTitle}"` : "missing"}, og:image: ${ogImage ? `"${ogImage}"` : "missing"}`,
      structuredEvidence: {
        id: "ev-seo-opengraph-incomplete",
        affectedTarget: "<head> OpenGraph Tags",
        observation: `og:title: ${ogTitle ? `"${ogTitle}"` : "missing"}, og:image: ${ogImage ? `"${ogImage}"` : "missing"}`,
        expectedCondition: "Both og:title and og:image tags declared",
        evidenceType: "dom-inspection",
        metadata: { hasOgTitle: Boolean(ogTitle), hasOgImage: Boolean(ogImage) },
      },
      affectedTarget: "<head> OpenGraph Tags",
      recommendation: "Add og:title, og:description, and og:image tags.",
      codeSnippet: '<meta property="og:title" content="..." />\n<meta property="og:image" content="..." />',
    });
  } else {
    passedChecks.push({
      id: "seo-opengraph-present",
      category: "seo",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-seo-opengraph-present",
        affectedTarget: "<head> OpenGraph Tags",
        observation: "Both og:title and og:image tags are declared",
        expectedCondition: "OpenGraph metadata complete",
        evidenceType: "dom-inspection",
      },
      title: "OpenGraph Metadata Configured",
      detail: "Both og:title and og:image tags are declared.",
    });
  }

  // 6. Heading Hierarchy & H1 Check
  const { headings, h1Count, h1Instances } = extractHeadings(root);

  if (h1Count === 0) {
    findings.push({
      id: "seo-h1-missing",
      category: "seo",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Page Missing Main <h1> Heading",
      description: "No <h1> element was detected in the document body.",
      whyItMatters:
        "The <h1> heading defines the primary topic for readers and accessibility screen readers. Its absence weakens page semantics.",
      evidence: "<h1> → 0 instances found in document",
      structuredEvidence: {
        id: "ev-seo-h1-missing",
        affectedTarget: "Document Body",
        observation: "Zero <h1> headings detected in document",
        expectedCondition: "Single prominent <h1> heading defining primary topic",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "Document Body",
      recommendation: "Ensure each page contains a single prominent <h1> representing the main page topic.",
      codeSnippet: "<h1>Clear, Descriptive Main Title</h1>",
    });
  } else if (h1Count > 1) {
    findings.push({
      id: "seo-multiple-h1",
      category: "seo",
      severity: "low",
      priority: "investigate",
      state: "recommendation",
      confidence: "high",
      title: "Multiple <h1> Elements Detected",
      description: `Found ${h1Count} separate <h1> headings on the page.`,
      whyItMatters:
        "While technically valid in HTML5, having a single <h1> heading per page provides clearer semantic hierarchy for SEO crawlers and assistive technology.",
      evidence: `Found ${h1Count} separate <h1> headings`,
      structuredEvidence: {
        id: "ev-seo-multiple-h1",
        affectedTarget: "Heading Structure",
        observation: `Found ${h1Count} separate <h1> elements`,
        expectedCondition: "Single prominent <h1> heading",
        evidenceType: "dom-inspection",
        metadata: { h1Count },
      },
      affectedTarget: "Heading Structure",
      recommendation: "Structure sub-sections with <h2> and <h3>, reserving <h1> for the page title.",
      instancesCount: h1Count,
      instances: h1Instances,
    });
  } else {
    passedChecks.push({
      id: "seo-h1-valid",
      category: "seo",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-seo-h1-valid",
        affectedTarget: "Heading Structure",
        observation: `Single <h1> heading: "${h1Instances[0] || ""}"`,
        expectedCondition: "Single prominent <h1> heading",
        evidenceType: "dom-inspection",
      },
      title: "Single Clear <h1> Heading",
      detail: `Primary topic defined by: "${h1Instances[0] || ""}"`,
    });
  }

  // Check for heading skips (e.g. h1 followed directly by h3 or h4)
  let hasSkippedHeading = false;
  let skipEvidence = "";
  for (let i = 0; i < headings.length - 1; i++) {
    const curr = headings[i].level;
    const next = headings[i + 1].level;
    if (next > curr + 1) {
      hasSkippedHeading = true;
      skipEvidence = `H${curr} ("${headings[i].text}") jumps to H${next} ("${headings[i + 1].text}") without H${curr + 1}`;
      break;
    }
  }

  if (hasSkippedHeading) {
    findings.push({
      id: "seo-heading-hierarchy-skipped",
      category: "seo",
      severity: "low",
      priority: "investigate",
      state: "recommendation",
      confidence: "high",
      title: "Heading Level Hierarchy Skips Detected",
      description: "Headings do not follow a strict sequential order (e.g., an <h1> jumps directly to an <h3>).",
      whyItMatters:
        "Sequential heading levels help search engine crawlers and screen readers understand the nested semantic structure of your document.",
      evidence: skipEvidence,
      structuredEvidence: {
        id: "ev-seo-heading-hierarchy-skipped",
        affectedTarget: "Document Headings",
        observation: skipEvidence,
        expectedCondition: "Sequential heading levels without skips",
        evidenceType: "dom-inspection",
      },
      affectedTarget: "Document Headings",
      recommendation: "Avoid skipping heading levels; follow h1 with h2, h2 with h3, etc.",
    });
  }

  const robots = extractRobotsMeta(root);

  const seoData: SeoInspection = {
    title: rawTitle,
    titleLength,
    metaDescription: metaDesc,
    descriptionLength: descLength,
    canonicalUrl,
    robots,
    ogTitle,
    ogImage,
    h1Count,
    headings: headings.slice(0, 15),
  };

  return { seoData, findings, passedChecks };
}
