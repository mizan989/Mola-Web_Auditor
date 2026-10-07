import { Finding, PassedCheck, SeoInspection } from "@/types/audit";

export interface SeoAuditResult {
  seoData: SeoInspection;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

export function auditSeo(htmlText: string): SeoAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. Extract <title>
  const titleMatch = htmlText.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const rawTitle = titleMatch ? titleMatch[1].trim().replace(/\s+/g, " ") : null;
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
      evidence: `<title>${rawTitle}</title> (Length: ${titleLength})`,
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
      evidence: `<title>${rawTitle.slice(0, 65)}...</title> (Length: ${titleLength})`,
      affectedTarget: "<title>",
      recommendation: "Trim the title to under 65 characters to avoid awkward search snippet truncation.",
    });
  } else {
    passedChecks.push({
      id: "seo-title-valid",
      category: "seo",
      title: "Optimal Title Length",
      detail: `Title "${rawTitle}" is ${titleLength} characters (within the recommended 15–70 range).`,
    });
  }

  // 2. Extract <meta name="description">
  const metaDescMatch = htmlText.match(/<meta\b[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i) ||
    htmlText.match(/<meta\b[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i);
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
      evidence: '<meta name="description"> → not found',
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
      evidence: `content="${metaDesc}" (Length: ${descLength})`,
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
  const canonicalMatch = htmlText.match(/<link\b[^>]*rel=["']canonical["'][^>]*href=["']([^"']*)["']/i);
  const canonicalUrl = canonicalMatch ? canonicalMatch[1] : null;

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
      evidence: '<link rel="canonical" ...> → not found',
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
  const viewportMatch = htmlText.match(/<meta\b[^>]*name=["']viewport["'][^>]*content=["']([^"']*)["']/i);
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
      evidence: '<meta name="viewport" ...> → not found',
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

  // 5. OpenGraph Tags
  const ogTitleMatch = htmlText.match(/<meta\b[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i);
  const ogImageMatch = htmlText.match(/<meta\b[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["']/i);
  const ogTitle = ogTitleMatch ? ogTitleMatch[1] : null;
  const ogImage = ogImageMatch ? ogImageMatch[1] : null;

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
      evidence: `og:title: ${ogTitle || "missing"}, og:image: ${ogImage || "missing"}`,
      affectedTarget: "<head> OpenGraph Tags",
      recommendation: "Add og:title, og:description, and og:image tags.",
      codeSnippet: '<meta property="og:title" content="..." />\n<meta property="og:image" content="..." />',
    });
  } else {
    passedChecks.push({
      id: "seo-opengraph-present",
      category: "seo",
      title: "OpenGraph Metadata Configured",
      detail: `og:title and og:image tags are present.`,
    });
  }

  // 6. Heading Hierarchy & H1 Check
  const h1Matches = htmlText.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/gi) || [];
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
      evidence: "<h1> → 0 instances found",
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
      evidence: `Found ${h1Count} <h1> tags`,
      affectedTarget: "Heading Structure",
      recommendation: "Structure sub-sections with <h2> and <h3>, reserving <h1> for the page title.",
    });
  } else {
    passedChecks.push({
      id: "seo-h1-valid",
      category: "seo",
      title: "Single Clear <h1> Heading",
      detail: "Exactly one <h1> element defines the primary page topic.",
    });
  }

  // Extract headings
  const headings: { level: number; text: string }[] = [];
  const headingMatches = htmlText.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi);
  for (const match of headingMatches) {
    const text = match[2].replace(/<[^>]+>/g, "").trim().slice(0, 80);
    if (text) {
      headings.push({ level: parseInt(match[1], 10), text });
    }
  }

  const robotsMatch = htmlText.match(/<meta\b[^>]*name=["']robots["'][^>]*content=["']([^"']*)["']/i);

  const seoData: SeoInspection = {
    title: rawTitle,
    titleLength,
    metaDescription: metaDesc,
    descriptionLength: descLength,
    canonicalUrl,
    robots: robotsMatch ? robotsMatch[1] : null,
    ogTitle,
    ogImage,
    h1Count,
    headings: headings.slice(0, 10),
  };

  return { seoData, findings, passedChecks };
}
