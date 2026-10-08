import type {
  AuditContext,
  BoundedHttpResponse,
  DiscoveredResources,
  AuditContextMetadata,
  DetectedTechnology,
} from "../types/audit.ts";
import { detectTechnologies } from "./scanners/tech.ts";
import type { FetchResult } from "./scanners/http.ts";

/**
 * Extracts discovered subresources (scripts, stylesheets, images, iframes)
 * deterministically from bounded HTML text.
 */
export function extractDiscoveredResources(htmlText: string): DiscoveredResources {
  if (!htmlText) {
    return { scripts: [], stylesheets: [], images: [], iframes: [] };
  }

  const scripts: string[] = [];
  const scriptMatches = htmlText.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi);
  for (const m of scriptMatches) {
    if (m[1] && !scripts.includes(m[1])) {
      scripts.push(m[1]);
    }
  }

  const stylesheets: string[] = [];
  const linkMatches = htmlText.matchAll(/<link\b[^>]*\brel=["']stylesheet["'][^>]*\bhref=["']([^"']+)["']/gi);
  for (const m of linkMatches) {
    if (m[1] && !stylesheets.includes(m[1])) {
      stylesheets.push(m[1]);
    }
  }
  const linkMatchesRev = htmlText.matchAll(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["']stylesheet["']/gi);
  for (const m of linkMatchesRev) {
    if (m[1] && !stylesheets.includes(m[1])) {
      stylesheets.push(m[1]);
    }
  }

  const images: string[] = [];
  const imgMatches = htmlText.matchAll(/<img\b[^>]*\bsrc=["']([^"']+)["']/gi);
  for (const m of imgMatches) {
    if (m[1] && !images.includes(m[1])) {
      images.push(m[1]);
    }
  }

  const iframes: string[] = [];
  const iframeMatches = htmlText.matchAll(/<iframe\b[^>]*\bsrc=["']([^"']+)["']/gi);
  for (const m of iframeMatches) {
    if (m[1] && !iframes.includes(m[1])) {
      iframes.push(m[1]);
    }
  }

  return { scripts, stylesheets, images, iframes };
}

/**
 * Type guard to identify an authoritative AuditContext.
 */
export function isAuditContext(val: unknown): val is AuditContext {
  if (!val || typeof val !== "object") return false;
  const c = val as Partial<AuditContext>;
  return (
    typeof c.targetUrl === "string" &&
    typeof c.finalUrl === "string" &&
    Array.isArray(c.redirectChain) &&
    typeof c.headers === "object" &&
    typeof c.body === "object" &&
    typeof c.timing === "object"
  );
}

export interface BuildContextParams {
  targetUrl: string;
  finalUrl: string;
  scanMode?: "quick" | "deep";
  scanId: string;
  startTime: number;
  httpResult: FetchResult;
  validatedAddresses?: string[];
}

/**
 * Constructs an authoritative, shared AuditContext from validated target information
 * and controlled HTTP inspection telemetry.
 */
export function buildAuditContext(params: BuildContextParams): AuditContext {
  const {
    targetUrl,
    finalUrl,
    scanMode = "quick",
    scanId,
    startTime,
    httpResult,
    validatedAddresses,
  } = params;

  const hostname = new URL(finalUrl || targetUrl).hostname;
  const isHttps = (finalUrl || targetUrl).startsWith("https://");
  const ttfbMs = httpResult.info?.responseTimeMs || 0;
  const now = Date.now();

  const response: BoundedHttpResponse = {
    statusCode: httpResult.info?.statusCode || 0,
    statusText: httpResult.info?.statusText || "",
    protocol: httpResult.info?.protocol || (isHttps ? "HTTP/1.1 (TLS)" : "HTTP/1.1"),
    isHttps,
    responseTimeMs: ttfbMs,
    contentLength: httpResult.info?.contentLength || 0,
    contentType: httpResult.rawHeaders["content-type"] || "text/html",
  };

  const limitations: string[] = [];
  if (httpResult.isTruncated) {
    limitations.push(
      "Document payload exceeded the 2.5 MB inspection limit and was safely capped; downstream DOM nodes were truncated."
    );
  }

  const discoveredResources = extractDiscoveredResources(httpResult.htmlText);
  const technologyObservations: DetectedTechnology[] = detectTechnologies(
    httpResult.rawHeaders,
    httpResult.htmlText
  );

  const metadata: AuditContextMetadata = {
    scanId,
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 MolaWebAuditor/1.0",
    timestamp: new Date().toISOString(),
    isPartial: httpResult.isTruncated,
    validatedAddresses,
  };

  return {
    targetUrl,
    finalUrl,
    hostname,
    scanMode,
    redirectChain: httpResult.info?.redirectChain || [targetUrl],
    response,
    headers: httpResult.rawHeaders,
    body: {
      text: httpResult.htmlText,
      byteLength: httpResult.info?.contentLength || 0,
      isTruncated: httpResult.isTruncated,
    },
    timing: {
      startTime,
      ttfbMs,
      durationMs: now - startTime,
    },
    discoveredResources,
    technologyObservations,
    limitations,
    metadata,
  };
}

export interface PartialContextParams {
  targetUrl: string;
  scanMode?: "quick" | "deep";
  scanId: string;
  startTime: number;
  failureReason: string;
  partialHeaders?: Record<string, string>;
  partialHtml?: string;
  redirectChain?: string[];
  validatedAddresses?: string[];
}

/**
 * Constructs an incomplete / partial AuditContext for failed connections or halted scans.
 * Ensures unvalidated destinations or broken fetches are safely represented with explicit limitations.
 */
export function createPartialAuditContext(params: PartialContextParams): AuditContext {
  const {
    targetUrl,
    scanMode = "quick",
    scanId,
    startTime,
    failureReason,
    partialHeaders = {},
    partialHtml = "",
    redirectChain = [targetUrl],
    validatedAddresses,
  } = params;

  let hostname = "unknown";
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    // Keep fallback
  }

  const isHttps = targetUrl.startsWith("https://");
  const discoveredResources = extractDiscoveredResources(partialHtml);
  const technologyObservations = Object.keys(partialHeaders).length > 0 || partialHtml
    ? detectTechnologies(partialHeaders, partialHtml)
    : [];

  return {
    targetUrl,
    finalUrl: targetUrl,
    hostname,
    scanMode,
    redirectChain,
    response: {
      statusCode: 0,
      statusText: "Connection Failed",
      protocol: isHttps ? "HTTP/1.1 (TLS)" : "HTTP/1.1",
      isHttps,
      responseTimeMs: 0,
      contentLength: 0,
      contentType: partialHeaders["content-type"] || "unknown",
    },
    headers: partialHeaders,
    body: {
      text: partialHtml,
      byteLength: partialHtml.length,
      isTruncated: true,
    },
    timing: {
      startTime,
      ttfbMs: 0,
      durationMs: Date.now() - startTime,
    },
    discoveredResources,
    technologyObservations,
    limitations: [`Audit halted prematurely: ${failureReason}`],
    metadata: {
      scanId,
      userAgent: "MolaWebAuditor/1.0",
      timestamp: new Date().toISOString(),
      isPartial: true,
      failureReason,
      validatedAddresses,
    },
  };
}
