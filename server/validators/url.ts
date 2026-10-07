import net from "node:net";
import { isPrivateOrReservedIp } from "./ip.ts";
import { resolveAndValidateDns } from "./dns.ts";

export interface UrlValidationResult {
  isValid: boolean;
  normalizedUrl?: string;
  hostname?: string;
  resolvedAddresses?: string[];
  error?: string;
}

const ALLOWED_PORTS = new Set(["80", "443", ""]);

const FORBIDDEN_HOSTS = new Set([
  "localhost",
  "loopback",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "metadata.google.internal",
  "instance-data",
  "169.254.169.254",
  "metadata.aws",
]);

const FORBIDDEN_SUFFIXES = [
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

/**
 * Validates and sanitizes a URL's syntax, protocol, and hostname format against SSRF attacks.
 * Complies with SECURITY.md and PRD.md FR-001.
 */
export function validateAndSanitizeUrl(rawInput: string): UrlValidationResult {
  if (!rawInput || typeof rawInput !== "string") {
    return { isValid: false, error: "Website URL is required." };
  }

  let input = rawInput.trim();

  // Maximum URL length guardrail
  if (input.length > 2048) {
    return { isValid: false, error: "URL exceeds maximum permitted length of 2048 characters." };
  }

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

  // Protocol check: Only HTTP and HTTPS
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
    return { isValid: false, error: "URLs containing user credentials are not allowed." };
  }

  // Port restrictions: Only default HTTP(80) and HTTPS(443) ports are permitted
  if (!ALLOWED_PORTS.has(parsed.port)) {
    return {
      isValid: false,
      error: `Port '${parsed.port}' is not permitted. Only standard web ports (80, 443) are supported.`,
    };
  }

  // Explicit loopback and local names
  if (FORBIDDEN_HOSTS.has(hostname)) {
    return { isValid: false, error: "Scanning local, loopback, or cloud metadata endpoints is prohibited." };
  }

  // Forbidden domain suffixes
  for (const suffix of FORBIDDEN_SUFFIXES) {
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
    hostname,
  };
}

/**
 * Performs full validation including asynchronous DNS resolution and checking all resolved IP addresses.
 * Guarantees SSRF defense survives hostnames resolving to private addresses.
 */
export async function validateUrlAsync(rawInput: string): Promise<UrlValidationResult> {
  const syncResult = validateAndSanitizeUrl(rawInput);
  if (!syncResult.isValid || !syncResult.hostname) {
    return syncResult;
  }

  const dnsResult = await resolveAndValidateDns(syncResult.hostname);
  if (!dnsResult.isValid) {
    return {
      isValid: false,
      error: dnsResult.error || "DNS resolution failed or resolved to restricted destination.",
    };
  }

  return {
    ...syncResult,
    resolvedAddresses: dnsResult.addresses,
  };
}

export { isPrivateOrReservedIp } from "./ip.ts";
export { resolveAndValidateDns } from "./dns.ts";
