import type {
  ReconnaissanceMap,
  ReconTargetInfo,
  ReconRedirectHop,
  ReconBodyMetadata,
  ReconSecurityObservation,
  DiscoveredResources,
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

export interface CollectReconParams {
  inputUrl: string;
  normalizedUrl: string;
  finalUrl: string;
  redirectChain: string[];
  httpResult: FetchResult;
  validatedAddresses?: string[];
  discoveredResources?: DiscoveredResources;
  technologySignals?: DetectedTechnology[];
}

/**
 * Deterministically constructs a structured surface map of the target website before specialized checks.
 * Complies with Phase 3 specifications: Recon is evidence collection, not a finding engine.
 * Produces structured observations with clear provenance without bypassing SSRF controls.
 */
export function collectReconnaissance(params: CollectReconParams): ReconnaissanceMap {
  const {
    inputUrl,
    normalizedUrl,
    finalUrl,
    redirectChain,
    httpResult,
    validatedAddresses,
  } = params;

  // 1. Target Normalization and Port/Scheme Mapping
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(finalUrl || normalizedUrl);
  } catch {
    parsedUrl = new URL(normalizedUrl);
  }

  const scheme = (parsedUrl.protocol === "https:" ? "https" : "http") as "http" | "https";
  const defaultPort = scheme === "https" ? 443 : 80;
  const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : defaultPort;

  const targetInfo: ReconTargetInfo = {
    inputUrl,
    normalizedUrl,
    finalUrl,
    hostname: parsedUrl.hostname,
    scheme,
    port,
    ipAddresses: validatedAddresses || [],
  };

  // 2. Redirect Chain Mapping
  const hops: ReconRedirectHop[] = redirectChain.map((url, index) => ({
    hopNumber: index + 1,
    url,
  }));

  // 3. Status and Headers
  const rawHeaders = httpResult.rawHeaders || {};
  const status = {
    code: httpResult.info?.statusCode || 0,
    text: httpResult.info?.statusText || (httpResult.info?.statusCode === 200 ? "OK" : ""),
    protocol: httpResult.info?.protocol || (scheme === "https" ? "HTTP/1.1 (TLS)" : "HTTP/1.1"),
    ttfbMs: httpResult.info?.responseTimeMs || 0,
  };

  // 4. Bounded Body Metadata
  const htmlText = httpResult.htmlText || "";
  const byteLength = httpResult.info?.contentLength || (htmlText ? new TextEncoder().encode(htmlText).length : 0);
  const characterLength = htmlText.length;
  const isTruncated = Boolean(httpResult.isTruncated);

  let charset: string | undefined;
  const contentType = rawHeaders["content-type"] || "unknown";
  const contentTypeCharsetMatch = contentType.match(/charset=([^;]+)/i);
  if (contentTypeCharsetMatch) {
    charset = contentTypeCharsetMatch[1].trim();
  } else {
    const metaCharsetMatch = htmlText.match(/<meta\b[^>]*\bcharset=["']?([^"'>\s]+)/i);
    if (metaCharsetMatch) {
      charset = metaCharsetMatch[1].trim();
    }
  }

  const hasHtmlDoctype = /<!doctype\s+html\b/i.test(htmlText);

  const bodyMetadata: ReconBodyMetadata = {
    byteLength,
    characterLength,
    isTruncated,
    maxBodyLimitBytes: 2.5 * 1024 * 1024,
    contentType,
    charset,
    hasHtmlDoctype,
  };

  // 5. Discovered Resources
  const discoveredResources =
    params.discoveredResources || extractDiscoveredResources(htmlText);

  // 6. Technology Signals
  const technologySignals =
    params.technologySignals || detectTechnologies(rawHeaders, htmlText);

  // 7. Security-Relevant Observations (Pure evidence collection, NOT findings)
  const securityObservations: ReconSecurityObservation[] = [];
  const limitations: string[] = [];

  // Transport observations
  if (scheme === "https") {
    securityObservations.push({
      type: "tls-transport",
      observation: `Final destination connects securely over ${status.protocol}`,
      provenance: "transport",
      severity: "info",
    });
  } else {
    securityObservations.push({
      type: "plaintext-http",
      observation: "Final destination uses unencrypted plaintext HTTP protocol",
      provenance: "transport",
      severity: "warning",
    });
  }

  // Redirect observations
  if (redirectChain.length > 1) {
    securityObservations.push({
      type: "redirect-chain",
      observation: `Target redirected through ${redirectChain.length - 1} hop(s): ${redirectChain.join(" -> ")}`,
      provenance: "redirect",
      severity: "info",
    });

    const initialScheme = redirectChain[0].startsWith("https://") ? "https" : "http";
    const finalScheme = redirectChain[redirectChain.length - 1].startsWith("https://") ? "https" : "http";
    if (initialScheme === "http" && finalScheme === "https") {
      securityObservations.push({
        type: "http-to-https-upgrade",
        observation: "Automatic HTTP to HTTPS redirect upgrade verified",
        provenance: "redirect",
        severity: "info",
      });
    } else if (initialScheme === "https" && finalScheme === "http") {
      securityObservations.push({
        type: "https-to-http-downgrade",
        observation: "Insecure downgrade from HTTPS to HTTP observed in redirect chain",
        provenance: "redirect",
        severity: "warning",
      });
    }
  }

  // Header security signals
  if (rawHeaders["strict-transport-security"]) {
    securityObservations.push({
      type: "hsts-signal",
      observation: `HSTS header returned: ${rawHeaders["strict-transport-security"]}`,
      provenance: "header",
      severity: "info",
    });
  } else if (scheme === "https") {
    securityObservations.push({
      type: "hsts-signal-absent",
      observation: "Strict-Transport-Security header not returned by server",
      provenance: "header",
      severity: "warning",
    });
  }

  if (rawHeaders["content-security-policy"]) {
    securityObservations.push({
      type: "csp-signal",
      observation: `Content-Security-Policy header returned: ${rawHeaders["content-security-policy"].slice(0, 100)}...`,
      provenance: "header",
      severity: "info",
    });
  } else {
    securityObservations.push({
      type: "csp-signal-absent",
      observation: "Content-Security-Policy header not declared",
      provenance: "header",
      severity: "warning",
    });
  }

  if (rawHeaders["x-frame-options"]) {
    securityObservations.push({
      type: "xfo-signal",
      observation: `X-Frame-Options returned: ${rawHeaders["x-frame-options"]}`,
      provenance: "header",
      severity: "info",
    });
  }

  if (rawHeaders["x-content-type-options"]) {
    securityObservations.push({
      type: "xcto-signal",
      observation: `X-Content-Type-Options returned: ${rawHeaders["x-content-type-options"]}`,
      provenance: "header",
      severity: "info",
    });
  }

  if (rawHeaders["server"]) {
    securityObservations.push({
      type: "server-disclosed",
      observation: `Server software signature exposed: ${rawHeaders["server"]}`,
      provenance: "header",
      severity: "warning",
    });
  }

  if (rawHeaders["x-powered-by"]) {
    securityObservations.push({
      type: "powered-by-disclosed",
      observation: `X-Powered-By software exposed: ${rawHeaders["x-powered-by"]}`,
      provenance: "header",
      severity: "warning",
    });
  }

  // HTML / Subresource observations
  if (scheme === "https") {
    const allDiscovered = [
      ...discoveredResources.scripts,
      ...discoveredResources.stylesheets,
      ...discoveredResources.images,
      ...discoveredResources.iframes,
    ];
    const insecureSubresources = allDiscovered.filter((url) => url.startsWith("http://"));
    if (insecureSubresources.length > 0) {
      securityObservations.push({
        type: "insecure-subresource-signal",
        observation: `Discovered ${insecureSubresources.length} subresource(s) requesting unencrypted HTTP on HTTPS document. Sample: ${insecureSubresources[0]}`,
        provenance: "html",
        severity: "warning",
      });
    }
  }

  // Limitations
  if (isTruncated) {
    limitations.push(
      "Document body exceeded 2.5 MB inspection limit; subresource and technology signals are bounded to initial 2.5 MB stream."
    );
  }
  if (status.code === 0) {
    limitations.push("HTTP connection failed; remote host was unreachable.");
  }

  return {
    target: targetInfo,
    redirectChain: hops,
    status,
    headers: rawHeaders,
    bodyMetadata,
    discoveredResources,
    technologySignals,
    securityObservations,
    limitations,
    collectedAt: new Date().toISOString(),
  };
}
