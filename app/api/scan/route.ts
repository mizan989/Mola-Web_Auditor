import { NextRequest, NextResponse } from "next/server";
import { runWebsiteAudit } from "@/server/orchestrator";

// Concurrency limiter state (ISSUE-006)
const MAX_CONCURRENT_SCANS = 5;
let activeScansCount = 0;

// Rate limiter state: IP -> timestamps (ISSUE-005)
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 15;
const ipRequestHistory = new Map<string, number[]>();

// Maximum permitted request body size in bytes (ISSUE-007)
const MAX_REQUEST_BODY_BYTES = 4096;

/**
 * Periodically cleans up stale rate limiter entries to prevent memory leaks.
 */
function cleanupRateLimiter() {
  const now = Date.now();
  for (const [ip, timestamps] of ipRequestHistory.entries()) {
    const valid = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (valid.length === 0) {
      ipRequestHistory.delete(ip);
    } else {
      ipRequestHistory.set(ip, valid);
    }
  }
}

/**
 * Checks whether an IP has exceeded the allowed rate limit.
 */
function checkRateLimit(ip: string): boolean {
  cleanupRateLimiter();
  const now = Date.now();
  const timestamps = ipRequestHistory.get(ip) || [];
  const recent = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);

  if (recent.length >= MAX_REQUESTS_PER_WINDOW) {
    return false; // Rate limit exceeded
  }

  recent.push(now);
  ipRequestHistory.set(ip, recent);
  return true;
}

export async function POST(req: NextRequest) {
  // 1. Enforce Request Body Size Limit (ISSUE-007)
  const contentLengthHeader = req.headers.get("content-length");
  if (contentLengthHeader) {
    const contentLength = parseInt(contentLengthHeader, 10);
    if (!isNaN(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
      return NextResponse.json(
        { error: "Request payload too large. Maximum allowed size is 4KB.", status: "failed" },
        { status: 413 }
      );
    }
  }

  // 2. Client IP Rate Limiting (ISSUE-005)
  const clientIp =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "127.0.0.1";

  if (!checkRateLimit(clientIp)) {
    return NextResponse.json(
      {
        error: "Too many audit requests. Please wait a moment before initiating another scan.",
        status: "failed",
      },
      {
        status: 429,
        headers: { "Retry-After": "60" },
      }
    );
  }

  // 3. Concurrency Limits (ISSUE-006)
  if (activeScansCount >= MAX_CONCURRENT_SCANS) {
    return NextResponse.json(
      {
        error: "Auditor server is currently handling peak scan volume. Please try again in a few seconds.",
        status: "failed",
      },
      { status: 503 }
    );
  }

  activeScansCount++;

  try {
    const rawText = await req.text();
    if (rawText.length > MAX_REQUEST_BODY_BYTES) {
      return NextResponse.json(
        { error: "Request body exceeds size limit.", status: "failed" },
        { status: 413 }
      );
    }

    let body: { url?: unknown; mode?: unknown };
    try {
      body = JSON.parse(rawText);
    } catch {
      return NextResponse.json(
        { error: "Malformed JSON payload.", status: "failed" },
        { status: 400 }
      );
    }

    if (!body || typeof body.url !== "string" || !body.url.trim()) {
      return NextResponse.json(
        { error: "A valid target website URL is required.", status: "failed" },
        { status: 400 }
      );
    }

    const trimmedUrl = body.url.trim();
    if (trimmedUrl.length > 2048) {
      return NextResponse.json(
        { error: "Target URL exceeds maximum length of 2048 characters.", status: "failed" },
        { status: 400 }
      );
    }

    const scanMode = body.mode === "deep" ? "deep" : "quick";

    const result = await runWebsiteAudit({
      url: trimmedUrl,
      mode: scanMode,
    });

    return NextResponse.json(result, { status: 200 });
  } catch (error: unknown) {
    // 4. Sanitize Backend Errors (ISSUE-008)
    const rawMessage = error instanceof Error ? error.message : "Internal error";

    let sanitizedMessage = "An unexpected error occurred while auditing the target website.";
    let statusCode = 502;

    if (
      rawMessage.includes("prohibited") ||
      rawMessage.includes("reserved") ||
      rawMessage.includes("private") ||
      rawMessage.includes("Invalid URL") ||
      rawMessage.includes("Protocol") ||
      rawMessage.includes("Port") ||
      rawMessage.includes("credentials") ||
      rawMessage.includes("top-level domain")
    ) {
      sanitizedMessage = rawMessage;
      statusCode = 400;
    } else if (rawMessage.includes("redirect") || rawMessage.includes("Redirect")) {
      sanitizedMessage = rawMessage;
      statusCode = 400;
    } else if (rawMessage.includes("timed out") || rawMessage.includes("deadline exceeded")) {
      sanitizedMessage = "Connection timed out while auditing the target website.";
      statusCode = 504;
    } else if (rawMessage.includes("Failed to establish connection") || rawMessage.includes("ENOTFOUND")) {
      sanitizedMessage = "Unable to connect to the target website. The host may be unreachable or offline.";
      statusCode = 502;
    }

    return NextResponse.json(
      {
        error: sanitizedMessage,
        status: "failed",
      },
      { status: statusCode }
    );
  } finally {
    activeScansCount--;
  }
}
