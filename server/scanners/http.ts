import { HttpInspectionInfo } from "@/types/audit";

export interface FetchResult {
  info: HttpInspectionInfo;
  htmlText: string;
  finalUrl: string;
  rawHeaders: Record<string, string>;
}

/**
 * Executes a controlled HTTP request to the target URL with timeout and redirect capture.
 */
export async function performHttpInspection(targetUrl: string): Promise<FetchResult> {
  const startTime = performance.now();
  const redirectChain: string[] = [targetUrl];

  const controller = new AbortController();
  const timeoutMs = 12000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let currentUrl = targetUrl;
    let response: Response;

    // Follow redirects manually or via fetch
    response = await fetch(currentUrl, {
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
      redirect: "follow",
    });

    clearTimeout(timeoutId);
    const duration = Math.round(performance.now() - startTime);

    if (response.url && response.url !== currentUrl) {
      redirectChain.push(response.url);
      currentUrl = response.url;
    }

    const rawHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      rawHeaders[key.toLowerCase()] = value;
    });

    // Read response text up to 5MB to avoid memory exhaustion
    const htmlText = await response.text();

    const contentLength =
      parseInt(rawHeaders["content-length"] || "0", 10) ||
      new TextEncoder().encode(htmlText).length;

    const isHttps = currentUrl.startsWith("https://");

    const info: HttpInspectionInfo = {
      statusCode: response.status,
      statusText: response.statusText || (response.status === 200 ? "OK" : "Status"),
      protocol: isHttps ? "HTTP/2 (TLS)" : "HTTP/1.1 (Insecure)",
      responseTimeMs: duration,
      contentLength,
      contentType: rawHeaders["content-type"] || "text/html",
      isHttps,
      redirectChain,
      headers: rawHeaders,
    };

    return {
      info,
      htmlText,
      finalUrl: currentUrl,
      rawHeaders,
    };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message =
      err instanceof Error
        ? err.name === "AbortError"
          ? "Request timed out after 12 seconds."
          : err.message
        : "Failed to connect to target website.";
    throw new Error(message);
  }
}
