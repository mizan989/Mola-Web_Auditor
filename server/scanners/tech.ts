import type { DetectedTechnology } from "../../types/audit.ts";

/**
 * Detects website technologies using verifiable, evidence-based heuristics.
 * Fixed according to ISSUE-015 & ISSUE-016 (no loose substring false-positives;
 * Tailwind CSS requires verified stylesheet/CDN reference or distinctive class clusters).
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
    evidence: string,
    version?: string
  ) => {
    if (!techs.some((t) => t.name === name)) {
      techs.push({ name, category, confidence, evidence, version });
    }
  };

  // 1. Next.js
  const nextPoweredBy = headers["x-powered-by"]?.toLowerCase().includes("next.js");
  const nextStaticScript = htmlText.includes("/_next/static/chunks/");
  const nextAppId = htmlText.includes('id="__next"');
  if (nextPoweredBy || nextStaticScript || nextAppId) {
    const evidence = nextPoweredBy
      ? 'Header X-Powered-By: Next.js'
      : nextStaticScript
      ? 'Asset path: /_next/static/chunks/'
      : 'Root DOM node: id="__next"';
    add("Next.js", "Framework", 100, evidence);
    // Next.js implies React
    add("React", "Framework", 100, "Derived from confirmed Next.js application runtime");
  }

  // 2. React (standalone)
  if (!techs.some((t) => t.name === "React")) {
    const reactRoot = htmlText.includes("data-reactroot");
    const reactDomScript = /<script\b[^>]*src=["'][^"']*react(?:-dom)?(?:\.production|\.development)?\.js/i.test(htmlText);
    const reactHook = htmlText.includes("__REACT_DEVTOOLS_GLOBAL_HOOK__");

    if (reactRoot || reactDomScript || reactHook) {
      const evidence = reactRoot
        ? "DOM attribute: data-reactroot"
        : reactDomScript
        ? "Script tag referencing React bundle"
        : "DevTools hook signature: __REACT_DEVTOOLS_GLOBAL_HOOK__";
      add("React", "Framework", 95, evidence);
    }
  }

  // 3. Vue.js & Nuxt
  const nuxtAsset = htmlText.includes("/_nuxt/");
  const vueDataAttr = /data-v-[a-f0-9]{4,}/i.test(htmlText);
  const vueHook = htmlText.includes("__VUE__") || htmlText.includes("__vue__");

  if (nuxtAsset) {
    add("Nuxt", "Framework", 100, "Asset path: /_nuxt/");
    add("Vue.js", "Framework", 100, "Derived from confirmed Nuxt application runtime");
  } else if (vueDataAttr || vueHook) {
    const evidence = vueDataAttr ? "Scoped CSS attribute: data-v-*" : "Runtime global: __VUE__";
    add("Vue.js", "Framework", 95, evidence);
  }

  // 4. Svelte & SvelteKit
  const svelteClass = /class=["'][^"']*\bsvelte-[a-z0-9]+\b/i.test(htmlText);
  const svelteKitAsset = htmlText.includes("/_app/immutable/");
  if (svelteClass || svelteKitAsset) {
    const evidence = svelteKitAsset ? "SvelteKit build path: /_app/immutable/" : "Scoped class: svelte-*";
    add("Svelte", "Framework", 95, evidence);
  }

  // 5. Angular
  const ngVersionMatch = htmlText.match(/ng-version=["']([^"']+)["']/i);
  const ngApp = htmlText.includes("ng-app") || htmlText.includes("<app-root");
  if (ngVersionMatch) {
    add("Angular", "Framework", 100, `ng-version attribute: ${ngVersionMatch[1]}`, ngVersionMatch[1]);
  } else if (ngApp) {
    add("Angular", "Framework", 90, "Angular root directive or <app-root> tag");
  }

  // 6. Tailwind CSS (ISSUE-016: Rigorous evidence required, no generic flex/grid false positives)
  const twCdn = /<script\b[^>]*src=["'][^"']*(?:cdn\.tailwindcss\.com|tailwindcss\.js)/i.test(htmlText);
  const twStyle = /<link\b[^>]*href=["'][^"']*tailwind(?:css)?(?:\.min)?\.css/i.test(htmlText);
  // Distinctive Tailwind utility combinations with responsive, state, or arbitrary prefixes
  const twDistinctClasses = (htmlText.match(/\b(?:sm|md|lg|xl|2xl|hover|focus|dark|active):[a-z0-9-]+\b/g) || []).length;
  const twArbitrary = (htmlText.match(/\b(?:bg|text|border|w|h)-\[[^\]]+\]\b/g) || []).length;

  if (twCdn || twStyle) {
    add(
      "Tailwind CSS",
      "UI / Fonts",
      100,
      twCdn ? "Tailwind CDN script tag detected" : "Tailwind CSS stylesheet link detected"
    );
  } else if (twDistinctClasses >= 3 || twArbitrary >= 2) {
    add(
      "Tailwind CSS",
      "UI / Fonts",
      85,
      `Detected ${twDistinctClasses} prefixed utility classes and ${twArbitrary} arbitrary value directives`
    );
  }

  // 7. WordPress
  const wpTheme = htmlText.includes("/wp-content/themes/");
  const wpPlugin = htmlText.includes("/wp-content/plugins/");
  const wpGenMatch = htmlText.match(/<meta\b[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([^"']*)["']/i);
  if (wpTheme || wpPlugin || wpGenMatch) {
    const evidence = wpGenMatch
      ? `Meta generator: WordPress ${wpGenMatch[1]}`
      : wpTheme
      ? "Asset path: /wp-content/themes/"
      : "Asset path: /wp-content/plugins/";
    add("WordPress", "CMS", 100, evidence, wpGenMatch ? wpGenMatch[1] : undefined);
  }

  // 8. Shopify
  const shopifyCdn = htmlText.includes("cdn.shopify.com");
  const shopifyHeader = headers["x-shopid"] || headers["x-shopify-stage"];
  if (shopifyCdn || shopifyHeader) {
    add("Shopify", "CMS", 100, shopifyCdn ? "Shopify CDN asset path" : "Shopify response header");
  }

  // 9. Webflow
  const webflowAttr = htmlText.includes("data-wf-page") || htmlText.includes("data-wf-site");
  const webflowAsset = htmlText.includes("assets.website-files.com");
  if (webflowAttr || webflowAsset) {
    add("Webflow", "CMS", 100, webflowAttr ? "DOM attribute: data-wf-page" : "Assets host: website-files.com");
  }

  // 10. Ghost
  const ghostPortal = htmlText.includes("ghost-portal");
  const ghostGen = /<meta\b[^>]*name=["']generator["'][^>]*content=["']Ghost\s*([^"']*)["']/i.exec(htmlText);
  if (ghostPortal || ghostGen) {
    add("Ghost", "CMS", 95, ghostGen ? `Meta generator: ${ghostGen[0]}` : "Ghost portal script integration");
  }

  // 11. Hosting & CDNs (From authentic HTTP headers)
  const server = (headers["server"] || "").toLowerCase();
  const via = (headers["via"] || "").toLowerCase();

  if (server.includes("cloudflare") || headers["cf-ray"] || headers["cf-cache-status"]) {
    add("Cloudflare", "CDN / Host", 100, `Headers: cf-ray: ${headers["cf-ray"] || "active"}`);
  }

  if (server.includes("vercel") || headers["x-vercel-id"] || headers["x-vercel-cache"]) {
    add("Vercel", "CDN / Host", 100, `Headers: x-vercel-id: ${headers["x-vercel-id"] || "active"}`);
  }

  if (server.includes("netlify") || headers["x-nf-request-id"]) {
    add("Netlify", "CDN / Host", 100, `Headers: x-nf-request-id: ${headers["x-nf-request-id"] || "active"}`);
  }

  if (headers["x-amz-cf-id"] || via.includes("cloudfront")) {
    add("AWS CloudFront", "CDN / Host", 100, `Headers: x-amz-cf-id: ${headers["x-amz-cf-id"] || "active"}`);
  }

  if (server.includes("fastly") || headers["x-fastly-request-id"]) {
    add("Fastly", "CDN / Host", 100, `Headers: x-fastly-request-id: ${headers["x-fastly-request-id"] || "active"}`);
  }

  if (server.includes("github.com") || headers["x-github-request-id"]) {
    add("GitHub Pages", "CDN / Host", 100, `Headers: x-github-request-id: ${headers["x-github-request-id"] || "active"}`);
  }

  // 12. Web Servers
  if (server.includes("nginx")) {
    const ver = headers["server"].match(/nginx\/([\d.]+)/i);
    add("Nginx", "Server", 90, `Server header: ${headers["server"]}`, ver ? ver[1] : undefined);
  } else if (server.includes("apache")) {
    const ver = headers["server"].match(/apache\/([\d.]+)/i);
    add("Apache", "Server", 90, `Server header: ${headers["server"]}`, ver ? ver[1] : undefined);
  } else if (server.includes("caddy")) {
    add("Caddy", "Server", 90, `Server header: ${headers["server"]}`);
  }

  // 13. Analytics
  if (lowerHtml.includes("googletagmanager.com/gtag/js") || lowerHtml.includes("google-analytics.com/analytics.js")) {
    add("Google Analytics", "Analytics", 95, "Script integration: Google Analytics / Tag Manager");
  }

  if (lowerHtml.includes("plausible.io/js/script.js")) {
    add("Plausible Analytics", "Analytics", 100, "Script integration: plausible.io");
  }

  if (lowerHtml.includes("cdn.usefathom.com/script.js")) {
    add("Fathom Analytics", "Analytics", 100, "Script integration: usefathom.com");
  }

  if (lowerHtml.includes("posthog.com") && lowerHtml.includes("posthog-js")) {
    add("PostHog", "Analytics", 95, "Script integration: posthog-js");
  }

  // 14. Fonts & UI
  if (lowerHtml.includes("fonts.googleapis.com") || lowerHtml.includes("fonts.gstatic.com")) {
    add("Google Fonts", "UI / Fonts", 95, "Stylesheet link: fonts.googleapis.com");
  }

  return techs;
}
