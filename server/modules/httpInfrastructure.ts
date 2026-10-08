import type { AuditContext, Finding, PassedCheck, PerformanceMetrics } from "../../types/audit.ts";
import { isAuditContext } from "../context.ts";

export interface HttpInfrastructureResult {
  findings: Finding[];
  passedChecks: PassedCheck[];
  metrics?: Partial<PerformanceMetrics>;
}

export interface HttpInfrastructureOptions {
  responseTimeMs?: number;
  contentLength?: number;
  headers?: Record<string, string>;
  isTruncated?: boolean;
  statusCode?: number;
  isPartial?: boolean;
  failureReason?: string;
  finalUrl?: string;
}

/**
 * Specialized Audit Module: HTTP & Infrastructure (Phase 8).
 * Inspects low-level protocol health, response latency (TTFB), payload compression,
 * HTTP caching directives, body bounding limits, and connection failures.
 */
export function auditHttpInfrastructure(
  contextOrOptions: AuditContext | HttpInfrastructureOptions
): HttpInfrastructureResult {
  const isCtx = isAuditContext(contextOrOptions);

  const finalUrl = isCtx ? contextOrOptions.finalUrl : (contextOrOptions as HttpInfrastructureOptions).finalUrl || "";
  const responseTimeMs = isCtx
    ? contextOrOptions.timing.ttfbMs
    : (contextOrOptions as HttpInfrastructureOptions).responseTimeMs ?? 0;
  const contentLength = isCtx
    ? contextOrOptions.response.contentLength
    : (contextOrOptions as HttpInfrastructureOptions).contentLength ?? 0;
  const headers = isCtx
    ? contextOrOptions.headers
    : (contextOrOptions as HttpInfrastructureOptions).headers ?? {};
  const isTruncated = isCtx
    ? contextOrOptions.body.isTruncated
    : (contextOrOptions as HttpInfrastructureOptions).isTruncated ?? false;
  const statusCode = isCtx
    ? contextOrOptions.response.statusCode
    : (contextOrOptions as HttpInfrastructureOptions).statusCode ?? 200;
  const isPartial = isCtx
    ? Boolean(contextOrOptions.metadata?.isPartial)
    : (contextOrOptions as HttpInfrastructureOptions).isPartial ?? false;
  const failureReason = isCtx
    ? contextOrOptions.metadata?.failureReason
    : (contextOrOptions as HttpInfrastructureOptions).failureReason;

  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  // 1. Connection Failure check (Host offline, connection aborted, or DNS resolution failure)
  if (isPartial && statusCode === 0) {
    findings.push({
      id: "sec-connection-failed",
      category: "security",
      severity: "high",
      priority: "critical",
      state: "unable_to_check",
      confidence: "high",
      title: "Security Posture Incomplete Due to Connection Failure",
      description: failureReason || "Could not establish HTTP connection to evaluate security posture.",
      whyItMatters: "Security headers and document controls cannot be audited without a successful HTTP response.",
      evidence: `Connection failed: ${failureReason || "Unknown network error"}`,
      structuredEvidence: {
        id: "ev-sec-connection-failed",
        sourceUrl: finalUrl,
        observation: `Failed to connect: ${failureReason || "Network error"}`,
        expectedCondition: "Successful HTTP response received",
        evidenceType: "network-failure",
        limitations: "Audit halted prematurely; remote host was unreachable.",
      },
      affectedTarget: finalUrl,
      recommendation: "Ensure the target website is online, publicly resolvable, and accepting HTTP requests.",
      limitations: "Audit halted prematurely; remote host was unreachable.",
    });
    return { findings, passedChecks };
  }

  const encoding = headers["content-encoding"] || null;
  const cacheControl = headers["cache-control"] || null;
  const payloadKb = Math.round((contentLength / 1024) * 10) / 10;

  // 2. TTFB / Latency
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
      state: "observation",
      confidence: "medium",
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

  // 3. HTTP Compression (Brotli / Gzip)
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

  // 4. Cache-Control Header
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

  // 5. Body Size Truncation Limit (2.5 MB)
  if (isTruncated) {
    findings.push({
      id: "perf-payload-truncated",
      category: "performance",
      severity: "low",
      priority: "investigate",
      state: "observation",
      confidence: "high",
      title: "Document Payload Exceeded Inspection Limit",
      description: "The remote document body exceeded the maximum 2.5 MB inspection limit and was safely capped.",
      whyItMatters:
        "Extremely large HTML payloads degrade mobile network performance, CPU parsing time, and memory usage.",
      evidence: `Body stream reached maximum size limit (2.5 MB); parsing terminated safely`,
      structuredEvidence: {
        id: "ev-perf-payload-truncated",
        sourceUrl: finalUrl,
        affectedTarget: "HTTP Response Body",
        observation: "Body stream reached maximum size limit (2.5 MB); parsing terminated safely.",
        expectedCondition: "HTML payload within bounded stream inspection limit (<= 2.5 MB)",
        evidenceType: "stream-limit-inspection",
        limitations: "Document inspection truncated at 2.5 MB; downstream DOM nodes beyond this limit were not inspected.",
      },
      affectedTarget: "HTTP Response Body",
      recommendation: "Ensure initial server-rendered HTML documents remain under 1 MB.",
      limitations: "Document inspection truncated at 2.5 MB; downstream DOM nodes beyond this limit were not inspected.",
    });
  }

  return {
    findings,
    passedChecks,
    metrics: {
      ttfbMs: responseTimeMs,
      totalPayloadKb: payloadKb,
      compression: encoding,
      cacheControl,
    },
  };
}
