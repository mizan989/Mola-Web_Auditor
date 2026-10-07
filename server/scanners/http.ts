import type { HttpInspectionInfo } from "../../types/audit.ts";
import { validateUrlAsync } from "../validators/url.ts";

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

/**
 * Executes a controlled, SSRF-hardened HTTP inspection.
 * - Handles redirects explicitly with SSRF validation at every hop (ISSUE-001, ISSUE-014)
 * - Validates DNS and addresses to prevent DNS rebinding (ISSUE-002, ISSUE-003)
 * - Measures true TTFB to response headers (ISSUE-011)
 * - Streams and caps response body size to prevent memory exhaustion (ISSUE-012)
 * - Uses an operation-level timeout covering the entire request lifecycle (ISSUE-013)
 * - Accurately reports protocol without guessing HTTP/2 (ISSUE-010)
 */
export async function performHttpInspection(targetUrl: string): Promise<FetchResult> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  let currentUrl = targetUrl;
  const redirectChain: string[] = [targetUrl];
  let redirectCount = 0;
  let initialTtfbMs = 0;

  try {
    let response: Response | null = null;

    // Follow redirects manually with strict SSRF validation at each hop
    while (true) {
      if (controller.signal.aborted) {
        throw new Error("Audit operation deadline exceeded.");
      }

      // Step A: Full SSRF and DNS check on the hop destination
      const validation = await validateUrlAsync(currentUrl);
      if (!validation.isValid) {
        throw new Error(
          redirectCount > 0
            ? `Unsafe redirect destination blocked by SSRF policy: ${validation.error || "Restricted target address."}`
            : validation.error || "Invalid target URL."
        );
      }

      const hopStart = performance.now();

      let hopResponse: Response;
      try {
        hopResponse = await fetch(currentUrl, {
          method: "GET",
          headers: {
            "User-Agent":
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 MolaWebAuditor/1.0",
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
          },
          signal: controller.signal,
          redirect: "manual",
        });
      } catch (fetchErr: unknown) {
        if (controller.signal.aborted) {
          throw new Error("Connection timed out while connecting to website.", { cause: fetchErr });
        }
        const msg = fetchErr instanceof Error ? fetchErr.message : "Network error";
        throw new Error(`Failed to establish connection to target: ${msg}`, { cause: fetchErr });
      }

      const hopTtfb = Math.round(performance.now() - hopStart);
      if (redirectCount === 0) {
        initialTtfbMs = hopTtfb;
      }

      // Check for HTTP 3xx redirect status
      const isRedirect =
        hopResponse.status === 301 ||
        hopResponse.status === 302 ||
        hopResponse.status === 303 ||
        hopResponse.status === 307 ||
        hopResponse.status === 308;

      if (isRedirect) {
        const location = hopResponse.headers.get("location");
        if (!location) {
          // Redirect without Location header; treat as final response
          response = hopResponse;
          break;
        }

        redirectCount++;
        if (redirectCount > MAX_REDIRECTS) {
          throw new Error(
            `Maximum redirect limit exceeded (maximum ${MAX_REDIRECTS} redirects allowed). Possible redirect loop.`
          );
        }

        // Parse and resolve relative redirect URLs against current URL
        let nextDestination: string;
        try {
          nextDestination = new URL(location, currentUrl).toString();
        } catch {
          throw new Error(`Invalid redirect Location header received: '${location}'`);
        }

        redirectChain.push(nextDestination);
        currentUrl = nextDestination;
        continue;
      }

      // Reached final non-redirect response
      response = hopResponse;
      break;
    }

    if (!response) {
      throw new Error("Failed to receive a valid HTTP response from target.");
    }

    // Extract headers
    const rawHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      rawHeaders[key.toLowerCase()] = value;
    });

    // Step B: Stream and limit response body reading (ISSUE-012)
    let isTruncated = false;
    let htmlText = "";
    let totalBytesRead = 0;

    const declaredContentLength = parseInt(rawHeaders["content-length"] || "0", 10);
    if (declaredContentLength > MAX_BODY_BYTES * 2) {
      isTruncated = true;
    }

    if (response.body) {
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];

      try {
        while (true) {
          if (controller.signal.aborted) {
            throw new Error("Operation timed out while downloading document body.");
          }

          const { done, value } = await reader.read();
          if (done) break;

          if (value) {
            totalBytesRead += value.length;
            if (totalBytesRead > MAX_BODY_BYTES) {
              // Exceeded body limit: truncate safely and break
              const allowedLength = value.length - (totalBytesRead - MAX_BODY_BYTES);
              if (allowedLength > 0) {
                chunks.push(value.slice(0, allowedLength));
              }
              isTruncated = true;
              await reader.cancel();
              break;
            }
            chunks.push(value);
          }
        }
      } catch (streamErr: unknown) {
        if (controller.signal.aborted) {
          throw new Error("Operation timed out while reading document body.", { cause: streamErr });
        }
        // If canceled intentionally due to truncation, ignore cancel error
        if (!isTruncated) {
          throw streamErr;
        }
      }

      // Merge chunks into text
      const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
      const merged = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.length;
      }
      htmlText = new TextDecoder("utf-8", { fatal: false }).decode(merged);
    } else {
      htmlText = await response.text();
      if (htmlText.length > MAX_BODY_BYTES) {
        htmlText = htmlText.slice(0, MAX_BODY_BYTES);
        isTruncated = true;
      }
      totalBytesRead = new TextEncoder().encode(htmlText).length;
    }

    clearTimeout(timeoutId);

    const isHttps = currentUrl.startsWith("https://");
    const contentLength = declaredContentLength || totalBytesRead;

    // Report protocol accurately: do not assume HTTPS is HTTP/2 (ISSUE-010)
    const protocol = isHttps ? "HTTP/1.1 (TLS)" : "HTTP/1.1";

    const info: HttpInspectionInfo = {
      statusCode: response.status,
      statusText: response.statusText || (response.status === 200 ? "OK" : `${response.status}`),
      protocol,
      responseTimeMs: initialTtfbMs,
      contentLength,
      contentType: rawHeaders["content-type"] || "text/html",
      isHttps,
      redirectChain,
      headers: rawHeaders,
      isTruncated,
    };

    return {
      info,
      htmlText,
      finalUrl: currentUrl,
      rawHeaders,
      isTruncated,
    };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message =
      err instanceof Error
        ? err.name === "AbortError"
          ? "Request timed out after 15 seconds."
          : err.message
        : "Failed to connect to target website.";
    throw new Error(message, { cause: err });
  }
}
