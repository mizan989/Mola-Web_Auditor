import { DetectedTechnology } from "@/types/audit";

/**
 * Detects website technologies by analyzing HTTP headers, meta generator tags, script signatures, and DOM elements.
 * Complies with PRD.md F-018.
 */
export function detectTechnologies(
  headers: Record<string, string>,
  htmlText: string
): DetectedTechnology[] {
  const techs: DetectedTechnology[] = [];
  const lowerHtml = htmlText.toLowerCase();

  const add = (
    name: string,
    category: DetectedTechnology["category"],
    confidence: number,
    version?: string
  ) => {
    if (!techs.some((t) => t.name === name)) {
      techs.push({ name, category, confidence, version });
    }
  };

  // 1. Next.js
  if (
    headers["x-powered-by"]?.toLowerCase().includes("next.js") ||
    lowerHtml.includes("__next") ||
    lowerHtml.includes("/_next/static/") ||
    lowerHtml.includes("id=\"__next\"")
  ) {
    add("Next.js", "Framework", 100);
  }

  // 2. React
  if (
    lowerHtml.includes("react") ||
    lowerHtml.includes("__react") ||
    lowerHtml.includes("data-reactroot") ||
    lowerHtml.includes("/_next/") ||
    lowerHtml.includes("react-dom")
  ) {
    add("React", "Framework", 95);
  }

  // 3. Vue.js / Nuxt
  if (lowerHtml.includes("data-v-") || lowerHtml.includes("__vue__") || lowerHtml.includes("/_nuxt/")) {
    add("Vue.js", "Framework", 95);
  }
  if (lowerHtml.includes("/_nuxt/") || lowerHtml.includes("__nuxt")) {
    add("Nuxt", "Framework", 100);
  }

  // 4. Svelte / SvelteKit
  if (lowerHtml.includes("__svelte") || lowerHtml.includes("svelte-") || lowerHtml.includes("/_app/immutable/")) {
    add("Svelte", "Framework", 90);
  }

  // 5. Angular
  if (lowerHtml.includes("ng-version") || lowerHtml.includes("ng-app") || lowerHtml.includes("ng-binding")) {
    const versionMatch = htmlText.match(/ng-version=["']([^"']+)["']/i);
    add("Angular", "Framework", 95, versionMatch ? versionMatch[1] : undefined);
  }

  // 6. Tailwind CSS
  if (
    lowerHtml.includes("tailwindcss") ||
    lowerHtml.includes("tailwind") ||
    /(?:class=["'][^"']*\b(?:flex|grid|items-center|justify-between|px-|py-|text-sm)\b[^"']*["'])/.test(htmlText)
  ) {
    add("Tailwind CSS", "UI / Fonts", 85);
  }

  // 7. WordPress
  if (
    lowerHtml.includes("/wp-content/") ||
    lowerHtml.includes("/wp-includes/") ||
    lowerHtml.includes("wp-json") ||
    headers["link"]?.includes("wp-json")
  ) {
    const generatorMatch = htmlText.match(/name=["']generator["'] content=["']wordpress\s*([^"']*)["']/i);
    add("WordPress", "CMS", 100, generatorMatch ? generatorMatch[1] : undefined);
  }

  // 8. Shopify
  if (
    lowerHtml.includes("cdn.shopify.com") ||
    lowerHtml.includes("shopify.com") ||
    headers["x-shopid"]
  ) {
    add("Shopify", "CMS", 100);
  }

  // 9. Webflow
  if (lowerHtml.includes("data-wf-page") || lowerHtml.includes("assets.website-files.com")) {
    add("Webflow", "CMS", 100);
  }

  // 10. Ghost
  if (lowerHtml.includes("ghost-portal") || lowerHtml.includes("generator\" content=\"ghost")) {
    add("Ghost", "CMS", 95);
  }

  // 11. Hosting & CDNs
  const server = (headers["server"] || "").toLowerCase();
  const via = (headers["via"] || "").toLowerCase();

  if (server.includes("cloudflare") || headers["cf-ray"] || headers["cf-cache-status"]) {
    add("Cloudflare", "CDN / Host", 100);
  }

  if (server.includes("vercel") || headers["x-vercel-id"] || headers["x-vercel-cache"]) {
    add("Vercel", "CDN / Host", 100);
  }

  if (server.includes("netlify") || headers["x-nf-request-id"]) {
    add("Netlify", "CDN / Host", 100);
  }

  if (headers["x-amz-cf-id"] || via.includes("cloudfront")) {
    add("AWS CloudFront", "CDN / Host", 95);
  }

  if (server.includes("fastly") || headers["x-fastly-request-id"]) {
    add("Fastly", "CDN / Host", 95);
  }

  if (server.includes("github.com") || headers["x-github-request-id"]) {
    add("GitHub Pages", "CDN / Host", 100);
  }

  // 12. Web Servers
  if (server.includes("nginx")) {
    const ver = headers["server"].match(/nginx\/([\d.]+)/i);
    add("Nginx", "Server", 90, ver ? ver[1] : undefined);
  } else if (server.includes("apache")) {
    const ver = headers["server"].match(/apache\/([\d.]+)/i);
    add("Apache", "Server", 90, ver ? ver[1] : undefined);
  } else if (server.includes("caddy")) {
    add("Caddy", "Server", 90);
  }

  // 13. Analytics
  if (
    lowerHtml.includes("google-analytics.com") ||
    lowerHtml.includes("googletagmanager.com") ||
    lowerHtml.includes("gtag(")
  ) {
    add("Google Analytics", "Analytics", 95);
  }

  if (lowerHtml.includes("plausible.io") || lowerHtml.includes("plausible.js")) {
    add("Plausible Analytics", "Analytics", 100);
  }

  if (lowerHtml.includes("usefathom.com")) {
    add("Fathom Analytics", "Analytics", 100);
  }

  if (lowerHtml.includes("posthog.com") || lowerHtml.includes("posthog-js")) {
    add("PostHog", "Analytics", 95);
  }

  // 14. Fonts & UI
  if (lowerHtml.includes("fonts.googleapis.com") || lowerHtml.includes("fonts.gstatic.com")) {
    add("Google Fonts", "UI / Fonts", 95);
  }

  if (lowerHtml.includes("fontawesome") || lowerHtml.includes("fa-") || lowerHtml.includes("font-awesome")) {
    add("Font Awesome", "UI / Fonts", 85);
  }

  return techs;
}
