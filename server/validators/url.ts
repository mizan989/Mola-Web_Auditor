import net from "node:net";

export interface UrlValidationResult {
  isValid: boolean;
  normalizedUrl?: string;
  error?: string;
}

/**
 * Validates and sanitizes a URL against SSRF attacks and unsafe target ranges.
 * Complies with SECURITY.md and PRD.md FR-001.
 */
export function validateAndSanitizeUrl(rawInput: string): UrlValidationResult {
  if (!rawInput || typeof rawInput !== "string") {
    return { isValid: false, error: "Website URL is required." };
  }

  let input = rawInput.trim();

  // Prepend https:// if no protocol provided
  if (!/^https?:\/\//i.test(input)) {
    input = `https://${input}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return { isValid: false, error: "Invalid URL syntax. Please enter a valid website address." };
  }

  // Protocol check
  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== "http:" && protocol !== "https:") {
    return {
      isValid: false,
      error: `Protocol '${protocol}' is not allowed. Only HTTP and HTTPS are supported.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Empty or whitespace hostname
  if (!hostname) {
    return { isValid: false, error: "Hostname cannot be empty." };
  }

  // Reject credentials in URL (user:pass@host)
  if (parsed.username || parsed.password) {
    return { isValid: false, error: "URLs with credentials (user:pass) are not allowed." };
  }

  // Explicit loopback and local names
  const forbiddenHosts = [
    "localhost",
    "loopback",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
    "instance-data",
  ];
  if (forbiddenHosts.includes(hostname)) {
    return { isValid: false, error: "Scanning local, loopback, or cloud metadata endpoints is prohibited." };
  }

  // Forbidden domain suffixes
  const forbiddenSuffixes = [
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".home.arpa",
    ".onion",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
  ];
  for (const suffix of forbiddenSuffixes) {
    if (hostname.endsWith(suffix)) {
      return { isValid: false, error: `Domains ending in '${suffix}' are internal or reserved and cannot be scanned.` };
    }
  }

  // If hostname is an IP address, check against private and reserved CIDR ranges
  if (net.isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      return { isValid: false, error: "Target resolved to a private or reserved network IP address." };
    }
  }

  // Ensure hostname has a TLD or valid dot structure
  if (!hostname.includes(".") && hostname !== "localhost") {
    return { isValid: false, error: "Hostname must include a valid top-level domain." };
  }

  return {
    isValid: true,
    normalizedUrl: parsed.toString(),
  };
}

/**
 * Checks whether an IP address belongs to RFC 1918, Link-local, Loopback, or Multicast ranges.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (ip === "127.0.0.1" || ip === "0.0.0.0" || ip === "::1") {
    return true;
  }

  const v4 = net.isIPv4(ip);
  if (v4) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4) return true;

    const [a, b] = parts;

    // 0.0.0.0/8 (Current network)
    if (a === 0) return true;
    // 10.0.0.0/8 (Private RFC 1918)
    if (a === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (Link Local / Cloud Metadata)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (Private RFC 1918)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (Private RFC 1918)
    if (a === 192 && b === 168) return true;
    // 100.64.0.0/10 (Carrier Grade NAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 224.0.0.0/4 (Multicast)
    if (a >= 224 && a <= 239) return true;
    // 240.0.0.0/4 (Reserved)
    if (a >= 240) return true;

    return false;
  }

  // IPv6 checks
  const lower = ip.toLowerCase();
  if (
    lower.startsWith("fc") || // ULA
    lower.startsWith("fd") || // ULA
    lower.startsWith("fe8") || // Link-local
    lower.startsWith("fe9") ||
    lower.startsWith("fea") ||
    lower.startsWith("feb") ||
    lower.startsWith("::ffff:127.") || // IPv4-mapped loopback
    lower.startsWith("::ffff:10.") || // IPv4-mapped private
    lower.startsWith("::ffff:192.168.")
  ) {
    return true;
  }

  return false;
}
