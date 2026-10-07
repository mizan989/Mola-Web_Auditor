import { NextRequest, NextResponse } from "next/server";
import { runWebsiteAudit } from "@/server/orchestrator";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => null);

    if (!body || typeof body.url !== "string") {
      return NextResponse.json(
        { error: "A valid website URL is required." },
        { status: 400 }
      );
    }

    const { url, mode } = body;
    const result = await runWebsiteAudit({
      url,
      mode: mode === "deep" ? "deep" : "quick",
    });

    return NextResponse.json(result, { status: 200 });
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : "An unexpected audit failure occurred.";

    const status = message.includes("prohibited") ||
      message.includes("reserved") ||
      message.includes("Invalid URL")
      ? 400
      : 502;

    return NextResponse.json(
      {
        error: message,
        status: "failed",
      },
      { status }
    );
  }
}
