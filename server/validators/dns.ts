import dns from "node:dns/promises";
import net from "node:net";
import { isPrivateOrReservedIp } from "./ip.ts";

export interface DnsValidationResult {
  isValid: boolean;
  addresses: string[];
  error?: string;
}

/**
 * Resolves a hostname via DNS and validates all resolved IP addresses (both IPv4 and IPv6)
 * against private, loopback, link-local, and reserved ranges to prevent SSRF and DNS rebinding.
 */
export async function resolveAndValidateDns(hostname: string): Promise<DnsValidationResult> {
  const cleanHost = hostname.trim().toLowerCase();

  // If already an IP address, directly validate it
  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      return {
        isValid: false,
        addresses: [cleanHost],
        error: `Target address '${cleanHost}' is a private or reserved network destination.`,
      };
    }
    return {
      isValid: true,
      addresses: [cleanHost],
    };
  }

  try {
    // Resolve both IPv4 and IPv6 addresses
    const lookupResults = await dns.lookup(cleanHost, { all: true });

    if (!lookupResults || lookupResults.length === 0) {
      return {
        isValid: false,
        addresses: [],
        error: `DNS resolution failed: no IP addresses found for host '${cleanHost}'.`,
      };
    }

    const addresses = lookupResults.map((entry) => entry.address);

    // Verify EVERY resolved address against SSRF rules
    for (const address of addresses) {
      if (isPrivateOrReservedIp(address)) {
        return {
          isValid: false,
          addresses,
          error: `Target host '${cleanHost}' resolved to non-public/private IP '${address}'. Access denied.`,
        };
      }
    }

    return {
      isValid: true,
      addresses,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown DNS lookup error";
    return {
      isValid: false,
      addresses: [],
      error: `DNS lookup failed for host '${cleanHost}': ${message}`,
    };
  }
}
