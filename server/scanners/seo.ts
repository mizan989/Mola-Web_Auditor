import { Finding, PassedCheck, SeoInspection } from "@/types/audit";

export interface SeoAuditResult {
  seoData: SeoInspection;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

/**
 * Strips HTML tags and collapses whitespace from a string snippet.
 */
function cleanText(raw: string): string {
  return raw.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
}

/**
 * Audits technical search engine optimization (SEO) factors.
 * Complies with ISSUE-017 (concrete document-structure analysis and attached evidence).
 */
export function auditSeo(htmlText: string): SeoAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. Document <title>
  const titleMatch = htmlText.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const rawTitle = titleMatch ? cleanText(titleMatch[1]) : null;
  const titleLength = rawTitle ? rawTitle.length : 0;

  if (!rawTitle) {
    findings.push({
      id: "seo-title-missing",
      category: "seo",
      severity: "high",
      priority: "critical",
      title: "Document <title> Tag Missing",
      description: "The HTML document has no <title> tag inside the <head> element.",
      whyItMatters:
        "The <title> tag is the primary textual signal for search engine ranking algorithms and is displayed as the clickable headline in search snippets and browser tabs.",
      evidence: '<head> contains no <title>...</title> element',
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
      title: "Document <title> Is Too Brief",
      description: `The page title is only ${titleLength} characters long ("${rawTitle}").`,
      whyItMatters:
        "Extremely short page titles miss the opportunity to convey relevant keywords, brand clarity, and context to search engines.",
      evidence: `<title>${rawTitle}</title> (Observed length: ${titleLength} chars)`,
      affectedTarget: "<title>",
      recommendation: "Expand the title to 30–65 characters including primary product or topic keywords.",
    });
  } else if (titleLength > 70) {
    findings.push({
      id: "seo-title-long",
      category: "seo",
      severity: "low",
      priority: "recommended",
      title: "Document <title> May Be Truncated in SERP",
      description: `The page title is ${titleLength} characters long (exceeds typical 60–70 character desktop limit).`,
      whyItMatters:
        "Search engines automatically truncate excessively long titles in search engine results pages with an ellipsis ('…').",
      evidence: `<title>${rawTitle.slice(0, 65)}...</title> (Observed length: ${titleLength} chars)`,
      affectedTarget: "<title>",
      recommendation: "Trim the title to under 65 characters to avoid awkward search snippet truncation.",
    });
  } else {
    passedChecks.push({
      id: "seo-title-valid",
      category: "seo",
      title: "Optimal Title Length",
      detail: `Title "${rawTitle}" is ${titleLength} characters (within recommended 15–70 range).`,
    });
  }

  // 2. Extract <meta name="description">
  const metaDescMatch =
    htmlText.match(/<meta\b[^>]*\bname=["']description["'][^>]*\bcontent=["']([^"']*)["']/i) ||
    htmlText.match(/<meta\b[^>]*\bcontent=["']([^"']*)["'][^>]*\bname=["']description["']/i);
  const metaDesc = metaDescMatch ? metaDescMatch[1].trim() : null;
  const descLength = metaDesc ? metaDesc.length : 0;

  if (!metaDesc) {
    findings.push({
      id: "seo-meta-description-missing",
      category: "seo",
      severity: "medium",
      priority: "fix-first",
      title: "Meta Description Tag Missing",
      description: "No <meta name=\"description\"> tag was found on the page.",
      whyItMatters:
        "Search engines display this snippet below your page title. A compelling description directly influences organic Click-Through-Rate (CTR).",
      evidence: '<meta name="description"> not found in <head>',
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
      title: "Meta Description Is Abnormally Short",
      description: `The meta description contains only ${descLength} characters.`,
      whyItMatters:
        "Short descriptions may cause search engines to substitute arbitrary body text in search results instead of your intended copy.",
      evidence: `content="${metaDesc}" (Observed length: ${descLength} chars)`,
      affectedTarget: '<meta name="description">',
      recommendation: "Flesh out the meta description to between 120 and 160 characters.",
    });
  } else {
    passedChecks.push({
      id: "seo-meta-description-valid",
      category: "seo",
      title: "Meta Description Present",
      detail: `Meta description contains ${descLength} characters.`,
    });
  }

  // 3. Canonical URL
  const canonicalMatch = htmlText.match(/<link\b[^>]*\brel=["']canonical["'][^>]*\bhref=["']([^"']*)["']/i);
  const canonicalUrl = canonicalMatch ? canonicalMatch[1].trim() : null;

  if (!canonicalUrl) {
    findings.push({
      id: "seo-canonical-missing",
      category: "seo",
      severity: "medium",
      priority: "recommended",
      title: "Canonical Link Tag Missing",
      description: "No <link rel=\"canonical\"> tag was found in the page header.",
      whyItMatters:
        "Without a canonical URL, search engines can split link equity across URL variations (e.g. http vs https, trailing slashes, tracking query parameters).",
      evidence: '<link rel="canonical" ...> not found in <head>',
      affectedTarget: "<head> Links",
      recommendation: "Declare a self-referential canonical URL tag.",
      codeSnippet: '<link rel="canonical" href="https://example.com/page" />',
    });
  } else {
    passedChecks.push({
      id: "seo-canonical-present",
      category: "seo",
      title: "Canonical Link Declared",
      detail: `Canonical points to ${canonicalUrl}`,
    });
  }

  // 4. Mobile Viewport Meta Tag
  const viewportMatch = htmlText.match(/<meta\b[^>]*\bname=["']viewport["'][^>]*\bcontent=["']([^"']*)["']/i);
  if (!viewportMatch) {
    findings.push({
      id: "seo-viewport-missing",
      category: "seo",
      severity: "high",
      priority: "critical",
      title: "Mobile Responsive Viewport Meta Tag Missing",
      description: "The document does not define a standard mobile viewport tag.",
      whyItMatters:
        "Mobile browsers will render the page at desktop widths and scale down, destroying mobile legibility and severely harming Google Mobile-First indexing.",
      evidence: '<meta name="viewport" ...> not found in document',
      affectedTarget: "<head>",
      recommendation: "Include the standard responsive viewport meta tag.",
      codeSnippet: '<meta name="viewport" content="width=device-width, initial-scale=1.0" />',
    });
  } else {
    passedChecks.push({
      id: "seo-viewport-present",
      category: "seo",
      title: "Responsive Viewport Configured",
      detail: `Viewport: ${viewportMatch[1]}`,
    });
  }

  // 5. OpenGraph & Social Sharing Meta Tags
  const ogTitleMatch = htmlText.match(/<meta\b[^>]*\bproperty=["']og:title["'][^>]*\bcontent=["']([^"']*)["']/i);
  const ogImageMatch = htmlText.match(/<meta\b[^>]*\bproperty=["']og:image["'][^>]*\bcontent=["']([^"']*)["']/i);
  const ogTitle = ogTitleMatch ? ogTitleMatch[1].trim() : null;
  const ogImage = ogImageMatch ? ogImageMatch[1].trim() : null;

  if (!ogTitle || !ogImage) {
    findings.push({
      id: "seo-opengraph-incomplete",
      category: "seo",
      severity: "low",
      priority: "recommended",
      title: "Social Sharing OpenGraph Tags Incomplete",
      description: `Missing essential social preview metadata (${!ogTitle ? "og:title " : ""}${!ogImage ? "og:image" : ""}).`,
      whyItMatters:
        "When your link is shared on Slack, Discord, Twitter/X, or LinkedIn, it will fail to render a rich link preview card with thumbnail imagery.",
      evidence: `og:title: ${ogTitle ? `"${ogTitle}"` : "missing"}, og:image: ${ogImage ? `"${ogImage}"` : "missing"}`,
      affectedTarget: "<head> OpenGraph Tags",
      recommendation: "Add og:title, og:description, and og:image tags.",
      codeSnippet: '<meta property="og:title" content="..." />\n<meta property="og:image" content="..." />',
    });
  } else {
    passedChecks.push({
      id: "seo-opengraph-present",
      category: "seo",
      title: "OpenGraph Metadata Configured",
      detail: "Both og:title and og:image tags are declared.",
    });
  }

  // 6. Heading Hierarchy & H1 Check
  const h1Matches = Array.from(htmlText.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi));
  const h1Count = h1Matches.length;

  if (h1Count === 0) {
    findings.push({
      id: "seo-h1-missing",
      category: "seo",
      severity: "medium",
      priority: "fix-first",
      title: "Page Missing Main <h1> Heading",
      description: "No <h1> element was detected in the document body.",
      whyItMatters:
        "The <h1> heading defines the primary topic for readers and accessibility screen readers. Its absence weakens page semantics.",
      evidence: "<h1> → 0 instances found in document",
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
      title: "Multiple <h1> Elements Detected",
      description: `Found ${h1Count} separate <h1> headings on the page.`,
      whyItMatters:
        "While technically valid in HTML5, having a single <h1> heading per page provides clearer semantic hierarchy for SEO crawlers and assistive technology.",
      evidence: `Found ${h1Count} separate <h1> headings`,
      affectedTarget: "Heading Structure",
      recommendation: "Structure sub-sections with <h2> and <h3>, reserving <h1> for the page title.",
      instancesCount: h1Count,
      instances: h1Matches.map((m) => cleanText(m[1]).slice(0, 60)),
    });
  } else {
    passedChecks.push({
      id: "seo-h1-valid",
      category: "seo",
      title: "Single Clear <h1> Heading",
      detail: `Primary topic defined by: "${cleanText(h1Matches[0][1]).slice(0, 60)}"`,
    });
  }

  // Extract structured headings
  const headings: { level: number; text: string }[] = [];
  const headingMatches = htmlText.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi);
  for (const match of headingMatches) {
    const text = cleanText(match[2]).slice(0, 80);
    if (text) {
      headings.push({ level: parseInt(match[1], 10), text });
    }
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
      title: "Heading Level Hierarchy Skips Detected",
      description: "Headings do not follow a strict sequential order (e.g., an <h1> jumps directly to an <h3>).",
      whyItMatters:
        "Sequential heading levels help search engine crawlers and screen readers understand the nested semantic structure of your document.",
      evidence: skipEvidence,
      affectedTarget: "Document Headings",
      recommendation: "Avoid skipping heading levels; follow h1 with h2, h2 with h3, etc.",
    });
  }

  const robotsMatch = htmlText.match(/<meta\b[^>]*\bname=["']robots["'][^>]*\bcontent=["']([^"']*)["']/i);

  const seoData: SeoInspection = {
    title: rawTitle,
    titleLength,
    metaDescription: metaDesc,
    descriptionLength: descLength,
    canonicalUrl,
    robots: robotsMatch ? robotsMatch[1].trim() : null,
    ogTitle,
    ogImage,
    h1Count,
    headings: headings.slice(0, 15),
  };

  return { seoData, findings, passedChecks };
}
