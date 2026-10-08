import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import { URL } from "node:url";
import type { HttpInspectionInfo } from "../../types/audit.ts";
import { validateUrlAsync } from "../validators/url.ts";
import { isPrivateOrReservedIp } from "../validators/ip.ts";

export interface FetchResult {
  info: HttpInspectionInfo;
  htmlText: string;
  finalUrl: string;
  rawHeaders: Record<string, string>;
  isTruncated: boolean;
}

export const MAX_REDIRECTS = 5;
export const MAX_BODY_BYTES = 2.5 * 1024 * 1024; // 2.5 MB maximum response body
export const SCAN_TIMEOUT_MS = 15000; // 15 seconds total operation deadline
export const HOP_TIMEOUT_MS = 10000; // 10 seconds per hop

export type LookupFunction = (
  hostname: string,
  options: dns.LookupOptions,
  callback: (
    err: NodeJS.ErrnoException | null,
    address: string | dns.LookupAddress[],
    family?: number
  ) => void
) => void;

/**
 * Phase 13: Connection-time DNS Rebinding Defense.
 *
 * Intercepts socket address resolution at the exact moment of connection,
 * preventing Time-Of-Check to Time-Of-Use (TOCTOU) DNS rebinding attacks.
 */
export function defaultSafeLookup(
  hostname: string,
  options: dns.LookupOptions,
  callback: (
    err: NodeJS.ErrnoException | null,
    address: string | dns.LookupAddress[],
    family?: number
  ) => void
): void {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err, address, family);

    if (Array.isArray(address)) {
      for (const item of address) {
        if (isPrivateOrReservedIp(item.address)) {
          const rebindingError: NodeJS.ErrnoException = new Error(
            `DNS rebinding blocked: Target host '${hostname}' resolved to private or restricted address (${item.address}) at connection time.`
          );
          rebindingError.code = "ERR_SSRF_DNS_REBINDING";
          return callback(rebindingError, [], 4);
        }
      }
      return callback(null, address, family);
    } else {
      if (isPrivateOrReservedIp(address)) {
        const rebindingError: NodeJS.ErrnoException = new Error(
          `DNS rebinding blocked: Target host '${hostname}' resolved to private or restricted address (${address}) at connection time.`
        );
        rebindingError.code = "ERR_SSRF_DNS_REBINDING";
        return callback(rebindingError, "", family);
      }
      return callback(null, address, family);
    }
  });
}

let activeLookup: LookupFunction = defaultSafeLookup;

/**
 * Injects a custom lookup function for adversarial testing or environment-specific resolution.
 */
export function setCustomLookup(fn: LookupFunction | null): void {
  activeLookup = fn || defaultSafeLookup;
}

export interface HopResult {
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  bodyText: string;
  isTruncated: boolean;
  contentLength: number;
  ttfbMs: number;
  locationHeader: string | null;
  isRedirect: boolean;
}

/**
 * Executes a single HTTP/HTTPS hop with connection-time DNS rebinding defense,
 * streaming bounded body read, and per-hop timeout enforcement.
 */
export function executeSingleHop(
  urlStr: string,
  signal: AbortSignal,
  hopTimeoutMs: number = HOP_TIMEOUT_MS
): Promise<HopResult> {
  return new Promise((resolve, reject) => {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlStr);
    } catch {
      return reject(new Error(`Invalid URL '${urlStr}'`));
    }

    const isHttps = parsedUrl.protocol === "https:";
    const transport = isHttps ? https : http;
    const startTime = performance.now();
    let isSettled = false;

    const requestOptions: https.RequestOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: `${parsedUrl.pathname || "/"}${parsedUrl.search || ""}`,
      method: "GET",
      headers: {
        Host: parsedUrl.host,
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 MolaWebAuditor/1.0",
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
      },
      lookup: activeLookup,
      timeout: hopTimeoutMs,
      servername: isHttps ? parsedUrl.hostname : undefined,
    };

    const req = transport.request(requestOptions, (res) => {
      const ttfbMs = Math.round(performance.now() - startTime);
      const statusCode = res.statusCode || 0;
      const statusText = res.statusMessage || (statusCode === 200 ? "OK" : `${statusCode}`);

      const rawHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(res.headers)) {
        if (value !== undefined) {
          rawHeaders[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
        }
      }

      const isRedirect =
        statusCode === 301 ||
        statusCode === 302 ||
        statusCode === 303 ||
        statusCode === 307 ||
        statusCode === 308;

      const locationHeader = rawHeaders["location"] || null;

      if (isRedirect && locationHeader) {
        res.resume();
        isSettled = true;
        return resolve({
          statusCode,
          statusText,
          headers: rawHeaders,
          bodyText: "",
          isTruncated: false,
          contentLength: 0,
          ttfbMs,
          locationHeader,
          isRedirect: true,
        });
      }

      const chunks: Buffer[] = [];
      let totalBytesRead = 0;
      let isTruncated = false;

      const declaredLength = parseInt(rawHeaders["content-length"] || "0", 10);
      if (declaredLength > MAX_BODY_BYTES * 2) {
        isTruncated = true;
      }

      res.on("data", (chunk: Buffer) => {
        totalBytesRead += chunk.length;
        if (totalBytesRead > MAX_BODY_BYTES) {
          const allowed = chunk.length - (totalBytesRead - MAX_BODY_BYTES);
          if (allowed > 0) {
            chunks.push(chunk.subarray(0, allowed));
          }
          isTruncated = true;
          req.destroy();
          res.destroy();
          if (!isSettled) {
            isSettled = true;
            const bodyBuffer = Buffer.concat(chunks);
            resolve({
              statusCode,
              statusText,
              headers: rawHeaders,
              bodyText: bodyBuffer.toString("utf-8"),
              isTruncated: true,
              contentLength: declaredLength || bodyBuffer.length,
              ttfbMs,
              locationHeader: null,
              isRedirect: false,
            });
          }
        } else {
          chunks.push(chunk);
        }
      });

      res.on("end", () => {
        if (isSettled) return;
        isSettled = true;
        const bodyBuffer = Buffer.concat(chunks);
        resolve({
          statusCode,
          statusText,
          headers: rawHeaders,
          bodyText: bodyBuffer.toString("utf-8"),
          isTruncated,
          contentLength: declaredLength || bodyBuffer.length,
          ttfbMs,
          locationHeader: null,
          isRedirect: false,
        });
      });

      res.on("close", () => {
        if (isTruncated && !isSettled) {
          isSettled = true;
          const bodyBuffer = Buffer.concat(chunks);
          resolve({
            statusCode,
            statusText,
            headers: rawHeaders,
            bodyText: bodyBuffer.toString("utf-8"),
            isTruncated: true,
            contentLength: declaredLength || bodyBuffer.length,
            ttfbMs,
            locationHeader: null,
            isRedirect: false,
          });
        }
      });

      res.on("error", (err) => {
        if (isTruncated) {
          if (isSettled) return;
          isSettled = true;
          const bodyBuffer = Buffer.concat(chunks);
          return resolve({
            statusCode,
            statusText,
            headers: rawHeaders,
            bodyText: bodyBuffer.toString("utf-8"),
            isTruncated: true,
            contentLength: declaredLength || bodyBuffer.length,
            ttfbMs,
            locationHeader: null,
            isRedirect: false,
          });
        }
        if (!isSettled) {
          isSettled = true;
          reject(err);
        }
      });
    });

    const onAbort = () => {
      req.destroy(new Error("Audit operation deadline exceeded."));
    };

    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener("abort", onAbort, { once: true });
    }

    req.on("timeout", () => {
      req.destroy(new Error(`Connection timed out after ${hopTimeoutMs}ms.`));
    });

    req.on("error", (err) => {
      signal.removeEventListener("abort", onAbort);
      if (isSettled) return;
      isSettled = true;
      reject(err);
    });

    req.end();
  });
}

/**
 * Executes a controlled, SSRF-hardened HTTP inspection.
 * - Handles redirects explicitly with SSRF validation at every hop (ISSUE-001, ISSUE-014, Phase 13)
 * - Validates DNS and addresses at actual socket connection time to eliminate DNS rebinding (Phase 13)
 * - Measures true TTFB to response headers (ISSUE-011)
 * - Streams and caps response body size to 2.5 MB to prevent memory exhaustion (ISSUE-012)
 * - Uses an operation-level timeout covering the entire request lifecycle (ISSUE-013)
 * - Accurately reports protocol without guessing HTTP/2 (ISSUE-010)
 */
export interface HttpInspectionOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

export async function performHttpInspection(
  targetUrl: string,
  options?: HttpInspectionOptions
): Promise<FetchResult> {
  const controller = new AbortController();
  const timeoutMs = options?.timeoutMs ?? SCAN_TIMEOUT_MS;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let externalAbortListener: (() => void) | undefined;
  if (options?.signal) {
    if (options.signal.aborted) {
      controller.abort();
    } else {
      externalAbortListener = () => controller.abort();
      options.signal.addEventListener("abort", externalAbortListener, { once: true });
    }
  }

  let currentUrl = targetUrl;
  const redirectChain: string[] = [targetUrl];
  let redirectCount = 0;
  let initialTtfbMs = 0;

  try {
    let finalHop: HopResult | null = null;

    // Follow redirects manually with strict SSRF validation at each hop
    while (true) {
      if (controller.signal.aborted) {
        throw new Error("Audit operation deadline exceeded.");
      }

      // Step A: Full SSRF and DNS check on the hop destination with bounded timeout and controller signal
      const validation = await validateUrlAsync(currentUrl, {
        signal: controller.signal,
        timeoutMs: Math.min(5000, HOP_TIMEOUT_MS),
      });
      if (!validation.isValid) {
        throw new Error(
          redirectCount > 0
            ? `Unsafe redirect destination blocked by SSRF policy: ${validation.error || "Restricted target address."}`
            : validation.error || "Invalid target URL."
        );
      }

      let hopResult: HopResult;
      try {
        hopResult = await executeSingleHop(currentUrl, controller.signal, HOP_TIMEOUT_MS);
      } catch (fetchErr: unknown) {
        if (controller.signal.aborted) {
          throw new Error("Connection timed out while connecting to website.", { cause: fetchErr });
        }
        const msg = fetchErr instanceof Error ? fetchErr.message : "Network error";
        throw new Error(`Failed to establish connection to target: ${msg}`, { cause: fetchErr });
      }

      if (redirectCount === 0) {
        initialTtfbMs = hopResult.ttfbMs;
      }

      // Check for HTTP 3xx redirect status
      if (hopResult.isRedirect && hopResult.locationHeader) {
        redirectCount++;
        if (redirectCount > MAX_REDIRECTS) {
          throw new Error(
            `Maximum redirect limit exceeded (maximum ${MAX_REDIRECTS} redirects allowed). Possible redirect loop.`
          );
        }

        // Parse and resolve relative redirect URLs against current URL
        let nextDestination: string;
        try {
          nextDestination = new URL(hopResult.locationHeader, currentUrl).toString();
        } catch {
          throw new Error(`Invalid redirect Location header received: '${hopResult.locationHeader}'`);
        }

        redirectChain.push(nextDestination);
        currentUrl = nextDestination;
        continue;
      }

      // Reached final non-redirect response
      finalHop = hopResult;
      break;
    }

    clearTimeout(timeoutId);

    if (!finalHop) {
      throw new Error("Failed to receive a valid HTTP response from target.");
    }

    const isHttps = currentUrl.startsWith("https://");
    const protocol = isHttps ? "HTTP/1.1 (TLS)" : "HTTP/1.1";

    const info: HttpInspectionInfo = {
      statusCode: finalHop.statusCode,
      statusText: finalHop.statusText,
      protocol,
      responseTimeMs: initialTtfbMs,
      contentLength: finalHop.contentLength,
      contentType: finalHop.headers["content-type"] || "text/html",
      isHttps,
      redirectChain,
      headers: finalHop.headers,
      isTruncated: finalHop.isTruncated,
    };

    return {
      info,
      htmlText: finalHop.bodyText,
      finalUrl: currentUrl,
      rawHeaders: finalHop.headers,
      isTruncated: finalHop.isTruncated,
    };
  } catch (err: unknown) {
    const message =
      err instanceof Error
        ? err.name === "AbortError"
          ? "Request timed out after 15 seconds."
          : err.message
        : "Failed to connect to target website.";
    throw new Error(message, { cause: err });
  } finally {
    clearTimeout(timeoutId);
    if (options?.signal && externalAbortListener) {
      options.signal.removeEventListener("abort", externalAbortListener);
    }
  }
}
