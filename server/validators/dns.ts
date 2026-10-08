import dns from "node:dns/promises";
import net from "node:net";
import { isPrivateOrReservedIp } from "./ip.ts";

export interface DnsValidationResult {
  isValid: boolean;
  addresses: string[];
  error?: string;
}

export interface DnsValidationOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

export const DEFAULT_DNS_TIMEOUT_MS = 5000;

export type DnsLookupFunction = (
  hostname: string,
  options: { all: boolean }
) => Promise<Array<{ address: string; family: number }>>;

let customDnsLookup: DnsLookupFunction | null = null;

/**
 * Injects a custom DNS lookup function for deterministic timeout/adversarial testing.
 */
export function setCustomDnsLookup(fn: DnsLookupFunction | null): void {
  customDnsLookup = fn;
}

/**
 * Resolves a hostname via DNS and validates all resolved IP addresses (both IPv4 and IPv6)
 * against private, loopback, link-local, and reserved ranges to prevent SSRF and DNS rebinding.
 * Bounded by a strict timeout and integrated with the audit operation deadline.
 */
export async function resolveAndValidateDns(
  hostname: string,
  options?: DnsValidationOptions
): Promise<DnsValidationResult> {
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

  const signal = options?.signal;
  if (signal?.aborted) {
    return {
      isValid: false,
      addresses: [],
      error: "DNS resolution aborted: operation deadline exceeded.",
    };
  }

  const timeoutMs = options?.timeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
  let timer: NodeJS.Timeout | undefined;
  let abortHandler: (() => void) | undefined;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const err: NodeJS.ErrnoException = new Error(`DNS resolution timed out after ${timeoutMs}ms for host '${cleanHost}'.`);
      err.code = "ETIMEDOUT";
      reject(err);
    }, timeoutMs);
  });

  const abortPromise = signal
    ? new Promise<never>((_, reject) => {
        abortHandler = () => {
          const err: NodeJS.ErrnoException = new Error("DNS resolution aborted: operation deadline exceeded.");
          err.code = "ABORT_ERR";
          reject(err);
        };
        signal.addEventListener("abort", abortHandler, { once: true });
      })
    : null;

  try {
    const lookupPromise: Promise<Array<{ address: string; family: number }>> = customDnsLookup
      ? customDnsLookup(cleanHost, { all: true })
      : (dns.lookup(cleanHost, { all: true }) as Promise<Array<{ address: string; family: number }>>);

    const raceList: Promise<Array<{ address: string; family: number }>>[] = [lookupPromise, timeoutPromise];
    if (abortPromise) raceList.push(abortPromise);

    const lookupResults = await Promise.race(raceList);

    if (!lookupResults || lookupResults.length === 0) {
      return {
        isValid: false,
        addresses: [],
        error: `DNS resolution failed: no IP addresses found for host '${cleanHost}'.`,
      };
    }

    const addresses = lookupResults.map((entry: { address: string }) => entry.address);

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
  } finally {
    if (timer) clearTimeout(timer);
    if (signal && abortHandler) {
      signal.removeEventListener("abort", abortHandler);
    }
  }
}
