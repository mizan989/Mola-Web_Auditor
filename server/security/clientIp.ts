/**
 * Phase 13: Trusted Client IP Extraction.
 *
 * Extracts trustworthy client IP address accounting for trusted reverse proxies
 * (Cloudflare, Vercel, AWS ALB, Nginx) while preventing X-Forwarded-For spoofing.
 */

export function extractClientIp(
  headers: Headers | Record<string, string | null | undefined>
): string {
  const getHeader = (name: string): string | null => {
    if (typeof (headers as Headers).get === "function") {
      return (headers as Headers).get(name);
    }
    const rec = headers as Record<string, string | null | undefined>;
    return rec[name.toLowerCase()] || rec[name] || null;
  };

  // 1. CF-Connecting-IP (authoritatively injected by Cloudflare Edge proxy)
  const cfIp = getHeader("cf-connecting-ip");
  if (cfIp && cfIp.trim()) {
    return cfIp.trim();
  }

  // 2. X-Real-IP (configured upstream reverse proxy)
  const realIp = getHeader("x-real-ip");
  if (realIp && realIp.trim()) {
    return realIp.trim();
  }

  // 3. X-Forwarded-For: Client IP in proxy chain
  const xForwardedFor = getHeader("x-forwarded-for");
  if (xForwardedFor) {
    const parts = xForwardedFor
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    if (parts.length > 0) {
      return parts[0];
    }
  }

  return "127.0.0.1";
}
