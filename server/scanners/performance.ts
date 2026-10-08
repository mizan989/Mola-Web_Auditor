import type { Finding, PassedCheck, PerformanceMetrics } from "../../types/audit.ts";

export interface PerformanceAuditResult {
  metrics: PerformanceMetrics;
  findings: Finding[];
  passedChecks: PassedCheck[];
}

export function auditPerformance(
  responseTimeMs: number,
  contentLength: number,
  headers: Record<string, string>,
  htmlText: string
): PerformanceAuditResult {
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  const encoding = headers["content-encoding"] || null;
  const cacheControl = headers["cache-control"] || null;
  const payloadKb = Math.round((contentLength / 1024) * 10) / 10;

  // Extract scripts, styles, images
  const scripts = htmlText.match(/<script\b[^>]*>/gi) || [];
  const stylesheets = htmlText.match(/<link\b[^>]*rel=["']stylesheet["'][^>]*>/gi) || [];
  const images = htmlText.match(/<img\b[^>]*>/gi) || [];

  const metrics: PerformanceMetrics = {
    ttfbMs: responseTimeMs,
    totalPayloadKb: payloadKb,
    compression: encoding,
    cacheControl,
    scriptsCount: scripts.length,
    stylesheetsCount: stylesheets.length,
    imagesCount: images.length,
  };

  // 1. TTFB / Response Latency
  if (responseTimeMs > 1200) {
    findings.push({
      id: "perf-high-ttfb",
      category: "performance",
      severity: "high",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "Slow Server Response Time (High TTFB)",
      description: `Server Time-To-First-Byte was measured at ${responseTimeMs}ms (>1200ms threshold).`,
      whyItMatters:
        "High initial server latency delays the browser from receiving HTML bytes, directly degrading Largest Contentful Paint (LCP) and user retention.",
      evidence: `Initial HTTP handshake & TTFB latency: ${responseTimeMs}ms`,
      structuredEvidence: {
        id: "ev-perf-high-ttfb",
        affectedTarget: "Edge Server / Application Server",
        observation: `Measured TTFB latency: ${responseTimeMs}ms`,
        expectedCondition: "TTFB latency under 600ms",
        evidenceType: "timing-measurement",
        metadata: { responseTimeMs },
      },
      affectedTarget: "Edge Server / Application Server",
      recommendation:
        "Implement edge caching (CDN), optimize database query execution, or activate server response streaming.",
    });
  } else if (responseTimeMs > 600) {
    findings.push({
      id: "perf-moderate-ttfb",
      category: "performance",
      severity: "medium",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Elevated Server Response Time",
      description: `Initial response time was ${responseTimeMs}ms (optimal is <300ms).`,
      whyItMatters:
        "Sub-optimal server response times delay resource discovery and initial page rendering.",
      evidence: `TTFB: ${responseTimeMs}ms`,
      structuredEvidence: {
        id: "ev-perf-moderate-ttfb",
        affectedTarget: "Origin Server",
        observation: `Measured TTFB latency: ${responseTimeMs}ms`,
        expectedCondition: "TTFB latency under 300ms",
        evidenceType: "timing-measurement",
        metadata: { responseTimeMs },
      },
      affectedTarget: "Origin Server",
      recommendation: "Review backend rendering performance and ensure caching headers are configured.",
    });
  } else {
    passedChecks.push({
      id: "perf-ttfb-fast",
      category: "performance",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-perf-ttfb-fast",
        affectedTarget: "Origin Server",
        observation: `Measured TTFB: ${responseTimeMs}ms`,
        expectedCondition: "TTFB latency under 600ms",
        evidenceType: "timing-measurement",
      },
      title: "Fast Server Response Time",
      detail: `TTFB measured at ${responseTimeMs}ms (well under recommended 600ms threshold).`,
    });
  }

  // 2. HTTP Compression (Brotli / Gzip)
  if (!encoding || (!encoding.includes("gzip") && !encoding.includes("br") && !encoding.includes("zstd"))) {
    findings.push({
      id: "perf-compression-missing",
      category: "performance",
      severity: "medium",
      priority: "fix-first",
      state: "confirmed",
      confidence: "high",
      title: "HTTP Payload Compression Disabled",
      description: "Response body was transferred without modern Brotli or Gzip compression.",
      whyItMatters:
        "Uncompressed text assets consume 60–80% more bandwidth, increasing transfer duration on mobile and slow connections.",
      evidence: `Content-Encoding: ${encoding || "none"} (Payload: ${payloadKb} KB)`,
      structuredEvidence: {
        id: "ev-perf-compression-missing",
        affectedTarget: "HTTP Compression Configuration",
        observation: `Content-Encoding: ${encoding || "none"}`,
        expectedCondition: "Active compression (brotli, gzip, or zstd)",
        evidenceType: "header-inspection",
        metadata: { payloadKb, encoding },
      },
      affectedTarget: "HTTP Compression Configuration",
      recommendation: "Enable Gzip or Brotli compression at your reverse proxy or hosting CDN level.",
      codeSnippet: "gzip on; gzip_types text/plain text/css application/json application/javascript;",
    });
  } else {
    passedChecks.push({
      id: "perf-compression-enabled",
      category: "performance",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-perf-compression-enabled",
        affectedTarget: "HTTP Compression Configuration",
        observation: `Content-Encoding: ${encoding}`,
        expectedCondition: "Payload compressed",
        evidenceType: "header-inspection",
      },
      title: "Payload Compression Active",
      detail: `Asset compressed with ${encoding}.`,
    });
  }

  // 3. Cache-Control for Document or Assets
  if (!cacheControl) {
    findings.push({
      id: "perf-cache-control-missing",
      category: "performance",
      severity: "low",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Cache-Control Policy Not Declared",
      description: "No Cache-Control header was provided in the server response.",
      whyItMatters:
        "Without an explicit caching policy, intermediate proxies and browsers may use heuristic caching or repeatedly re-fetch static content.",
      evidence: 'response.headers["cache-control"] → undefined',
      structuredEvidence: {
        id: "ev-perf-cache-control-missing",
        affectedTarget: "HTTP Response Headers",
        observation: 'response.headers["cache-control"] is undefined',
        expectedCondition: "Explicit Cache-Control header declared",
        evidenceType: "header-inspection",
      },
      affectedTarget: "HTTP Response Headers",
      recommendation:
        "Define Cache-Control directives appropriate for this resource (e.g. `public, max-age=3600` or `no-cache, must-revalidate` for dynamic HTML).",
      codeSnippet: "Cache-Control: public, max-age=0, must-revalidate",
    });
  } else {
    passedChecks.push({
      id: "perf-cache-control-present",
      category: "performance",
      state: "confirmed",
      confidence: "high",
      structuredEvidence: {
        id: "ev-perf-cache-control-present",
        affectedTarget: "HTTP Response Headers",
        observation: `Cache-Control: ${cacheControl}`,
        expectedCondition: "Cache-Control header configured",
        evidenceType: "header-inspection",
      },
      title: "Cache-Control Policy Configured",
      detail: `Cache-Control: ${cacheControl}`,
    });
  }

  // 4. Render-blocking scripts in <head>
  const headMatch = htmlText.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i);
  if (headMatch) {
    const headContent = headMatch[1];
    const blockingScripts =
      headContent.match(/<script\b(?![^>]*(?:async|defer|nomodule|type=["']module["']))[^>]*src=[^>]*>/gi) || [];

    if (blockingScripts.length > 0) {
      findings.push({
        id: "perf-render-blocking-scripts",
        category: "performance",
        severity: "medium",
        priority: "fix-first",
        state: "confirmed",
        confidence: "high",
        title: "Render-Blocking Scripts in <head>",
        description: `Found ${blockingScripts.length} synchronous <script> tags in the document <head>.`,
        whyItMatters:
          "Synchronous scripts halt HTML parsing until the script is fully downloaded and executed, directly delaying First Contentful Paint (FCP).",
        evidence: `Sample blocking script: ${blockingScripts[0]?.slice(0, 80) || ""}`,
        structuredEvidence: {
          id: "ev-perf-render-blocking-scripts",
          affectedTarget: "<head> scripts",
          observation: `Found ${blockingScripts.length} synchronous <script> tags in <head>`,
          expectedCondition: "Scripts deferred, async, or loaded as ES modules",
          evidenceType: "dom-inspection",
          metadata: { blockingCount: blockingScripts.length },
        },
        affectedTarget: "<head> scripts",
        recommendation: "Add `defer` or `async` to non-critical external scripts, or adopt ES modules.",
        codeSnippet: '<script src="..." defer></script>',
        instancesCount: blockingScripts.length,
        instances: blockingScripts.slice(0, 4),
      });
    } else {
      passedChecks.push({
        id: "perf-scripts-deferred",
        category: "performance",
        state: "not_detected",
        confidence: "high",
        structuredEvidence: {
          id: "ev-perf-scripts-deferred",
          affectedTarget: "<head> scripts",
          observation: "Zero synchronous render-blocking scripts detected in <head>",
          expectedCondition: "Scripts deferred or asynchronous",
          evidenceType: "dom-inspection",
        },
        title: "All Scripts Asynchronous or Deferred",
        detail: "No synchronous render-blocking scripts detected in document <head>.",
      });
    }
  }

  // 5. Image dimension declaration (CLS reduction)
  const imagesWithoutDimensions = images.filter(
    (img) => !/width=["']\d+/i.test(img) || !/height=["']\d+/i.test(img)
  );

  if (imagesWithoutDimensions.length > 0) {
    findings.push({
      id: "perf-images-missing-dimensions",
      category: "performance",
      severity: "low",
      priority: "recommended",
      state: "confirmed",
      confidence: "high",
      title: "Images Missing Explicit Dimensions",
      description: `${imagesWithoutDimensions.length} image(s) lack explicit width and height attributes.`,
      whyItMatters:
        "When browsers do not know an image's aspect ratio beforehand, the page layout shifts abruptly as images load, hurting Cumulative Layout Shift (CLS).",
      evidence: `Sample image tag: ${imagesWithoutDimensions[0]?.slice(0, 75) || ""}`,
      structuredEvidence: {
        id: "ev-perf-images-missing-dimensions",
        affectedTarget: "HTML <img> Elements",
        observation: `${imagesWithoutDimensions.length} <img> elements lack width and height attributes`,
        expectedCondition: "All <img> elements declare explicit width and height",
        evidenceType: "dom-inspection",
        metadata: { missingCount: imagesWithoutDimensions.length },
      },
      affectedTarget: "HTML <img> Elements",
      recommendation:
        "Specify explicit `width` and `height` attributes or CSS aspect-ratio on all image elements.",
      codeSnippet: '<img src="/photo.jpg" width="800" height="600" alt="..." />',
      instancesCount: imagesWithoutDimensions.length,
      instances: imagesWithoutDimensions.slice(0, 5),
    });
  }

  return { metrics, findings, passedChecks };
}
