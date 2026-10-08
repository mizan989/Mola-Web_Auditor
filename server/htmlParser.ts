import { parse, HTMLElement } from "node-html-parser";
import type { DiscoveredResources } from "../types/audit.ts";
import { validateInputLabelCandidate, validateImageAltCandidate } from "./candidateValidator.ts";

/**
 * Strips residual markup tags, decodes common HTML entities, and collapses whitespace.
 */
export function cleanText(raw: string): string {
  if (!raw) return "";
  return raw
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Defensive HTML document parser using node-html-parser.
 * Preserves the 2.5MB maximum body limit, handles malformed documents gracefully,
 * and isolates script/style block contents so deceptive strings are not parsed as DOM nodes.
 */
export function parseHtmlDocument(htmlText: string): HTMLElement {
  if (!htmlText || typeof htmlText !== "string") {
    return parse("", { comment: false, parseNoneClosedTags: true });
  }

  // Enforce memory-safe body limit (2.5MB)
  const maxBytes = 2.5 * 1024 * 1024;
  const boundedHtml = htmlText.length > maxBytes ? htmlText.slice(0, maxBytes) : htmlText;

  try {
    return parse(boundedHtml, {
      comment: false,
      parseNoneClosedTags: true,
      blockTextElements: {
        script: true,
        noscript: true,
        style: true,
        pre: true,
      },
    });
  } catch {
    // Return empty root on unexpected parser failure
    return parse("", { comment: false, parseNoneClosedTags: true });
  }
}

// ==========================================
// SEO & Meta Extractions
// ==========================================

export interface TitleExtraction {
  rawTitle: string | null;
  count: number;
}

export function extractDocumentTitle(root: HTMLElement): TitleExtraction {
  const titleEls = root.querySelectorAll("title");
  if (titleEls.length === 0) {
    return { rawTitle: null, count: 0 };
  }
  const rawTitle = cleanText(titleEls[0].textContent);
  return {
    rawTitle: rawTitle || null,
    count: titleEls.length,
  };
}

export interface MetaDescriptionExtraction {
  metaDesc: string | null;
  count: number;
}

export function extractMetaDescription(root: HTMLElement): MetaDescriptionExtraction {
  const metaEls = root.querySelectorAll("meta");
  const matching: string[] = [];

  for (const meta of metaEls) {
    const name = meta.getAttribute("name");
    if (name && name.toLowerCase() === "description") {
      const content = meta.getAttribute("content");
      if (content !== undefined) {
        matching.push(content.trim());
      }
    }
  }

  return {
    metaDesc: matching.length > 0 ? matching[0] : null,
    count: matching.length,
  };
}

export interface CanonicalExtraction {
  canonicalUrl: string | null;
  canonicals: string[];
}

export function extractCanonicalLinks(root: HTMLElement): CanonicalExtraction {
  const linkEls = root.querySelectorAll("link");
  const canonicals: string[] = [];

  for (const link of linkEls) {
    const rel = link.getAttribute("rel");
    if (rel && rel.toLowerCase().split(/\s+/).includes("canonical")) {
      const href = link.getAttribute("href");
      if (href) {
        canonicals.push(href.trim());
      }
    }
  }

  return {
    canonicalUrl: canonicals.length > 0 ? canonicals[0] : null,
    canonicals,
  };
}

export function extractViewportMeta(root: HTMLElement): string | null {
  const metaEls = root.querySelectorAll("meta");
  for (const meta of metaEls) {
    const name = meta.getAttribute("name");
    if (name && name.toLowerCase() === "viewport") {
      const content = meta.getAttribute("content");
      if (content !== undefined) {
        return content.trim();
      }
    }
  }
  return null;
}

export interface OpenGraphMeta {
  ogTitle: string | null;
  ogImage: string | null;
}

export function extractOpenGraphMeta(root: HTMLElement): OpenGraphMeta {
  const metaEls = root.querySelectorAll("meta");
  let ogTitle: string | null = null;
  let ogImage: string | null = null;

  for (const meta of metaEls) {
    const property = meta.getAttribute("property") || meta.getAttribute("name");
    if (property) {
      const propLower = property.toLowerCase();
      if (propLower === "og:title") {
        ogTitle = meta.getAttribute("content")?.trim() || null;
      } else if (propLower === "og:image") {
        ogImage = meta.getAttribute("content")?.trim() || null;
      }
    }
  }

  return { ogTitle, ogImage };
}

export function extractRobotsMeta(root: HTMLElement): string | null {
  const metaEls = root.querySelectorAll("meta");
  for (const meta of metaEls) {
    const name = meta.getAttribute("name");
    if (name && name.toLowerCase() === "robots") {
      const content = meta.getAttribute("content");
      if (content !== undefined) {
        return content.trim();
      }
    }
  }
  return null;
}

export interface HeadingItem {
  level: number;
  text: string;
}

export function extractHeadings(root: HTMLElement): {
  headings: HeadingItem[];
  h1Count: number;
  h1Instances: string[];
} {
  const headingEls = root.querySelectorAll("h1, h2, h3, h4, h5, h6");
  const headings: HeadingItem[] = [];
  const h1Instances: string[] = [];

  for (const el of headingEls) {
    const tag = el.tagName.toLowerCase();
    const level = parseInt(tag.replace("h", ""), 10);
    const text = cleanText(el.textContent).slice(0, 80);
    if (text) {
      headings.push({ level, text });
      if (level === 1) {
        h1Instances.push(text);
      }
    }
  }

  return {
    headings,
    h1Count: h1Instances.length,
    h1Instances,
  };
}

// ==========================================
// Accessibility (a11y) Extractions
// ==========================================

export interface HtmlLangExtraction {
  hasLang: boolean;
  lang: string | null;
  rawTag: string;
}

export function extractHtmlLanguage(root: HTMLElement): HtmlLangExtraction {
  // Query <html> element
  const htmlEl = root.querySelector("html") || (root.tagName === "HTML" ? root : null);
  if (!htmlEl) {
    return { hasLang: false, lang: null, rawTag: "<html> missing" };
  }

  const lang = htmlEl.getAttribute("lang")?.trim() || null;
  return {
    hasLang: Boolean(lang),
    lang,
    rawTag: htmlEl.rawAttrs ? `<html ${htmlEl.rawAttrs}>` : "<html>",
  };
}

export interface ImagesExtraction {
  allImagesCount: number;
  missingAlt: string[];
  totalImages: number;
}

export function extractImageAccessibility(root: HTMLElement): ImagesExtraction {
  const imgEls = root.querySelectorAll("img");
  const missingAlt: string[] = [];

  for (const img of imgEls) {
    const hasAlt = img.hasAttribute("alt");
    const evalResult = validateImageAltCandidate({
      hasAltAttribute: hasAlt,
      src: img.getAttribute("src") || undefined,
    });

    if (evalResult.outcome === "confirmed") {
      const outer = img.outerHTML ? img.outerHTML.replace(/\s+/g, " ").slice(0, 90) : "<img>";
      missingAlt.push(outer);
    }
  }

  return {
    allImagesCount: imgEls.length,
    missingAlt,
    totalImages: imgEls.length,
  };
}

export interface FormLabelsExtraction {
  totalInputs: number;
  unlabelledInputs: number;
  unlabelledSamples: string[];
  duplicateIds: string[];
}

export function extractFormLabels(root: HTMLElement): FormLabelsExtraction {
  // Collect all IDs referenced by <label for="...">
  const labelForIds = new Set<string>();
  const labelEls = root.querySelectorAll("label");
  for (const label of labelEls) {
    const forAttr = label.getAttribute("for");
    if (forAttr && forAttr.trim()) {
      labelForIds.add(forAttr.trim());
    }
  }

  // Detect duplicate IDs across all elements
  const seenIds = new Set<string>();
  const duplicateIdsSet = new Set<string>();
  const elementsWithId = root.querySelectorAll("[id]");
  for (const el of elementsWithId) {
    const id = el.getAttribute("id")?.trim();
    if (id) {
      if (seenIds.has(id)) {
        duplicateIdsSet.add(id);
      } else {
        seenIds.add(id);
      }
    }
  }

  // Query all form inputs
  const inputEls = root.querySelectorAll("input");
  let totalInputs = 0;
  let unlabelledInputs = 0;
  const unlabelledSamples: string[] = [];

  for (const input of inputEls) {
    const type = (input.getAttribute("type") || "text").toLowerCase().trim();

    // Check accessible naming sources:
    // 1. ARIA label or labelledby
    const ariaLabel = input.getAttribute("aria-label")?.trim();
    const ariaLabelledby = input.getAttribute("aria-labelledby")?.trim();
    const hasAria = Boolean(ariaLabel || ariaLabelledby);

    // 2. Title attribute
    const title = input.getAttribute("title")?.trim();
    const hasTitle = Boolean(title);

    // 3. Explicit association with <label for="id">
    const id = input.getAttribute("id")?.trim();
    const hasAssociatedLabelFor = Boolean(id && labelForIds.has(id));

    // 4. Wrapped inside <label> element
    const isWrappedInLabel = Boolean(input.closest("label"));

    const evalResult = validateInputLabelCandidate({
      type,
      id,
      hasAria,
      hasTitle,
      hasLabelFor: hasAssociatedLabelFor,
      isWrappedInLabel,
    });

    if (["hidden", "submit", "button", "reset", "image"].includes(type)) {
      continue;
    }

    totalInputs++;

    if (evalResult.outcome === "confirmed") {
      unlabelledInputs++;
      if (unlabelledSamples.length < 5) {
        const outer = input.outerHTML ? input.outerHTML.replace(/\s+/g, " ").slice(0, 90) : "<input>";
        unlabelledSamples.push(outer);
      }
    }
  }

  return {
    totalInputs,
    unlabelledInputs,
    unlabelledSamples,
    duplicateIds: Array.from(duplicateIdsSet),
  };
}

export interface LandmarksExtraction {
  hasMain: boolean;
  hasHeader: boolean;
  hasNav: boolean;
}

export function extractLandmarks(root: HTMLElement): LandmarksExtraction {
  const main = root.querySelector("main") || root.querySelector('[role="main"]');
  const header = root.querySelector("header") || root.querySelector('[role="banner"]');
  const nav = root.querySelector("nav") || root.querySelector('[role="navigation"]');

  return {
    hasMain: Boolean(main),
    hasHeader: Boolean(header),
    hasNav: Boolean(nav),
  };
}

// ==========================================
// Subresource & Media Extractions
// ==========================================

export function extractDiscoveredResourcesFromDom(root: HTMLElement): DiscoveredResources {
  const scripts: string[] = [];
  const scriptEls = root.querySelectorAll("script");
  for (const s of scriptEls) {
    const src = s.getAttribute("src");
    if (src && !scripts.includes(src)) {
      scripts.push(src);
    }
  }

  const stylesheets: string[] = [];
  const linkEls = root.querySelectorAll("link");
  for (const l of linkEls) {
    const rel = l.getAttribute("rel");
    if (rel && rel.toLowerCase().split(/\s+/).includes("stylesheet")) {
      const href = l.getAttribute("href");
      if (href && !stylesheets.includes(href)) {
        stylesheets.push(href);
      }
    }
  }

  const images: string[] = [];
  const imgEls = root.querySelectorAll("img");
  for (const img of imgEls) {
    const src = img.getAttribute("src");
    if (src && !images.includes(src)) {
      images.push(src);
    }
  }

  const iframes: string[] = [];
  const iframeEls = root.querySelectorAll("iframe");
  for (const ifr of iframeEls) {
    const src = ifr.getAttribute("src");
    if (src && !iframes.includes(src)) {
      iframes.push(src);
    }
  }

  return { scripts, stylesheets, images, iframes };
}

export interface ParsedScriptInfo {
  src: string;
  hasIntegrity: boolean;
  integrity?: string;
  isAsync: boolean;
  isDefer: boolean;
  isModule: boolean;
  isNoModule: boolean;
  inHead: boolean;
}

export function extractScripts(root: HTMLElement): ParsedScriptInfo[] {
  const scriptEls = root.querySelectorAll("script");
  const scripts: ParsedScriptInfo[] = [];

  for (const s of scriptEls) {
    const src = s.getAttribute("src");
    if (!src) continue;

    const integrity = s.getAttribute("integrity");
    const hasIntegrity = Boolean(integrity && /^sha(?:256|384|512)-/i.test(integrity));
    const isAsync = s.hasAttribute("async");
    const isDefer = s.hasAttribute("defer");
    const isNoModule = s.hasAttribute("nomodule");
    const type = (s.getAttribute("type") || "").toLowerCase().trim();
    const isModule = type === "module";

    // Determine if inside <head>
    const inHead = Boolean(s.closest("head"));

    scripts.push({
      src,
      hasIntegrity,
      integrity: integrity || undefined,
      isAsync,
      isDefer,
      isModule,
      isNoModule,
      inHead,
    });
  }

  return scripts;
}

export interface ParsedIframeInfo {
  src: string;
  hasSandbox: boolean;
  sandboxValue?: string;
  isLazy: boolean;
}

export function extractIframes(root: HTMLElement): ParsedIframeInfo[] {
  const iframeEls = root.querySelectorAll("iframe");
  const iframes: ParsedIframeInfo[] = [];

  for (const ifr of iframeEls) {
    const src = ifr.getAttribute("src") || "unknown-iframe";
    const hasSandbox = ifr.hasAttribute("sandbox");
    const sandboxValue = ifr.getAttribute("sandbox") || undefined;
    const loading = (ifr.getAttribute("loading") || "").toLowerCase().trim();
    const isLazy = loading === "lazy";

    iframes.push({
      src,
      hasSandbox,
      sandboxValue,
      isLazy,
    });
  }

  return iframes;
}

export interface ParsedLinkInfo {
  href: string;
  rel?: string;
  text: string;
}

export function extractLinks(root: HTMLElement): ParsedLinkInfo[] {
  const linkEls = root.querySelectorAll("a[href]");
  const links: ParsedLinkInfo[] = [];

  for (const a of linkEls) {
    const href = a.getAttribute("href");
    if (href) {
      links.push({
        href,
        rel: a.getAttribute("rel") || undefined,
        text: cleanText(a.textContent),
      });
    }
  }

  return links;
}

/**
 * Extracts all subresources loaded over plain HTTP on HTTPS targets.
 * Inspects DOM elements: <script src>, <link href>, <img src>, <iframe src>, <video src>, <audio src>, <source src>.
 * Excludes deceptive strings in script or style bodies.
 */
export function extractInsecureMixedContent(root: HTMLElement): string[] {
  const insecureUrls: string[] = [];

  const addIfInsecure = (url: string | undefined) => {
    if (url && url.toLowerCase().startsWith("http://") && !insecureUrls.includes(url)) {
      insecureUrls.push(url);
    }
  };

  // Scripts
  for (const s of root.querySelectorAll("script")) {
    addIfInsecure(s.getAttribute("src"));
  }

  // Stylesheets & preloaded links
  for (const l of root.querySelectorAll("link")) {
    addIfInsecure(l.getAttribute("href"));
  }

  // Images
  for (const img of root.querySelectorAll("img")) {
    addIfInsecure(img.getAttribute("src"));
  }

  // Iframes
  for (const ifr of root.querySelectorAll("iframe")) {
    addIfInsecure(ifr.getAttribute("src"));
  }

  // Audio / Video / Source media elements
  for (const media of root.querySelectorAll("video, audio, source")) {
    addIfInsecure(media.getAttribute("src"));
  }

  return insecureUrls;
}

/**
 * Identifies deprecated HTML elements present in the document.
 */
export function extractDeprecatedTags(root: HTMLElement): string[] {
  const deprecatedTagNames = ["center", "font", "marquee", "blink", "frame", "frameset", "applet", "strike"];
  const found: string[] = [];

  for (const tag of deprecatedTagNames) {
    const els = root.querySelectorAll(tag);
    if (els.length > 0) {
      found.push(`<${tag}>`);
    }
  }

  return found;
}

/**
 * Extracts charset declared in HTML meta tags.
 */
export function extractHtmlCharset(root: HTMLElement): string | null {
  const metaEls = root.querySelectorAll("meta");
  for (const meta of metaEls) {
    // 1. <meta charset="...">
    const charset = meta.getAttribute("charset");
    if (charset) {
      return charset.trim();
    }

    // 2. <meta http-equiv="content-type" content="...; charset=...">
    const httpEquiv = meta.getAttribute("http-equiv");
    if (httpEquiv && httpEquiv.toLowerCase() === "content-type") {
      const content = meta.getAttribute("content");
      if (content) {
        const match = content.match(/charset=([^;]+)/i);
        if (match) {
          return match[1].trim();
        }
      }
    }
  }

  return null;
}
