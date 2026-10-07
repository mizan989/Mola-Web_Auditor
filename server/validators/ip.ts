import net from "node:net";

/**
 * Parses an IPv4 address string into a 32-bit unsigned integer.
 * Returns null if invalid.
 */
export function ipv4ToNumber(ip: string): number | null {
  if (!net.isIPv4(ip)) return null;
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let num = 0;
  for (let i = 0; i < 4; i++) {
    const octet = Number(parts[i]);
    if (isNaN(octet) || octet < 0 || octet > 255 || parts[i] !== octet.toString()) {
      return null;
    }
    num = (num << 8) | octet;
  }
  return num >>> 0;
}

/**
 * Parses an IPv6 address string into an array of 8 16-bit words.
 * Handles :: shorthand, hex notation, and IPv4-mapped suffixes (e.g. ::ffff:192.0.2.1).
 * Returns null if invalid.
 */
export function parseIPv6(ip: string): number[] | null {
  if (!net.isIPv6(ip)) return null;

  let address = ip.toLowerCase();

  // Check for embedded IPv4 at the end (e.g., ::ffff:192.168.1.1)
  const lastColon = address.lastIndexOf(":");
  if (lastColon !== -1) {
    const possibleV4 = address.slice(lastColon + 1);
    if (net.isIPv4(possibleV4)) {
      const v4Parts = possibleV4.split(".").map(Number);
      if (v4Parts.length === 4) {
        const high = (v4Parts[0] << 8) | v4Parts[1];
        const low = (v4Parts[2] << 8) | v4Parts[3];
        const hexHigh = high.toString(16);
        const hexLow = low.toString(16);
        address = `${address.slice(0, lastColon)}:${hexHigh}:${hexLow}`;
      }
    }
  }

  const doubleColonIndex = address.indexOf("::");
  let words: number[];

  if (doubleColonIndex !== -1) {
    // Cannot have more than one "::"
    if (address.indexOf("::", doubleColonIndex + 2) !== -1) {
      return null;
    }

    const left = address.slice(0, doubleColonIndex);
    const right = address.slice(doubleColonIndex + 2);

    const leftWords = left.length > 0 ? left.split(":").map((w) => parseInt(w, 16)) : [];
    const rightWords = right.length > 0 ? right.split(":").map((w) => parseInt(w, 16)) : [];

    const missingCount = 8 - (leftWords.length + rightWords.length);
    if (missingCount < 1) return null;

    words = [...leftWords, ...new Array(missingCount).fill(0), ...rightWords];
  } else {
    words = address.split(":").map((w) => parseInt(w, 16));
  }

  if (words.length !== 8 || words.some((w) => isNaN(w) || w < 0 || w > 0xffff)) {
    return null;
  }

  return words;
}

/**
 * Checks whether an IPv4 address is in a private, loopback, link-local, multicast,
 * documentation, carrier-grade NAT, or reserved range.
 */
export function isPrivateOrReservedIPv4(ip: string): boolean {
  const num = ipv4ToNumber(ip);
  if (num === null) return true; // Fail closed if unparseable

  const octet1 = (num >>> 24) & 0xff;
  const octet2 = (num >>> 16) & 0xff;

  // 0.0.0.0/8 (Current network / "this" host - RFC 1122)
  if (octet1 === 0) return true;

  // 10.0.0.0/8 (Private - RFC 1918)
  if (octet1 === 10) return true;

  // 100.64.0.0/10 (Carrier-grade NAT - RFC 6598: 100.64.0.0 to 100.127.255.255)
  if (octet1 === 100 && octet2 >= 64 && octet2 <= 127) return true;

  // 127.0.0.0/8 (Loopback - RFC 1122)
  if (octet1 === 127) return true;

  // 169.254.0.0/16 (Link Local / Cloud Metadata - RFC 3927)
  if (octet1 === 169 && octet2 === 254) return true;

  // 172.16.0.0/12 (Private - RFC 1918: 172.16.0.0 to 172.31.255.255)
  if (octet1 === 172 && octet2 >= 16 && octet2 <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments - RFC 6890)
  if (octet1 === 192 && octet2 === 0 && ((num >>> 8) & 0xff) === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1 documentation - RFC 5737)
  if (octet1 === 192 && octet2 === 0 && ((num >>> 8) & 0xff) === 2) return true;

  // 192.88.99.0/24 (6to4 Relay Anycast - RFC 7526)
  if (octet1 === 192 && octet2 === 88 && ((num >>> 8) & 0xff) === 99) return true;

  // 192.168.0.0/16 (Private - RFC 1918)
  if (octet1 === 192 && octet2 === 168) return true;

  // 198.18.0.0/15 (Network benchmark tests - RFC 2544: 198.18.0.0 to 198.19.255.255)
  if (octet1 === 198 && (octet2 === 18 || octet2 === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2 documentation - RFC 5737)
  if (octet1 === 198 && octet2 === 51 && ((num >>> 8) & 0xff) === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3 documentation - RFC 5737)
  if (octet1 === 203 && octet2 === 0 && ((num >>> 8) & 0xff) === 113) return true;

  // 224.0.0.0/4 (Multicast - RFC 5771: 224.0.0.0 to 239.255.255.255)
  if (octet1 >= 224 && octet1 <= 239) return true;

  // 240.0.0.0/4 (Reserved / Future use - RFC 1112: 240.0.0.0 to 255.255.255.255)
  if (octet1 >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address is in a private, loopback, link-local, multicast,
 * unique-local, documentation, or reserved range. Also inspects IPv4-mapped and 6to4 addresses.
 */
export function isPrivateOrReservedIPv6(ip: string): boolean {
  const words = parseIPv6(ip);
  if (words === null) return true; // Fail closed if unparseable

  // ::/128 (Unspecified)
  if (words.every((w) => w === 0)) return true;

  // ::1/128 (Loopback)
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0 &&
    words[6] === 0 &&
    words[7] === 1
  ) {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:0:0/96)
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0xffff
  ) {
    const embeddedIpv4 = `${(words[6] >>> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >>> 8) & 0xff}.${words[7] & 0xff}`;
    return isPrivateOrReservedIPv4(embeddedIpv4);
  }

  // IPv4-translated (::ffff:0:0:0/96)
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0xffff &&
    words[5] === 0
  ) {
    const embeddedIpv4 = `${(words[6] >>> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >>> 8) & 0xff}.${words[7] & 0xff}`;
    return isPrivateOrReservedIPv4(embeddedIpv4);
  }

  // 64:ff9b::/96 (IPv4/IPv6 translation - RFC 6052)
  if (
    words[0] === 0x0064 &&
    words[1] === 0xff9b &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0
  ) {
    const embeddedIpv4 = `${(words[6] >>> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >>> 8) & 0xff}.${words[7] & 0xff}`;
    return isPrivateOrReservedIPv4(embeddedIpv4);
  }

  // 100::/64 (Discard-only - RFC 6666)
  if (words[0] === 0x0100 && words[1] === 0 && words[2] === 0 && words[3] === 0) {
    return true;
  }

  // 2001:db8::/32 (Documentation - RFC 3849)
  if (words[0] === 0x2001 && words[1] === 0x0db8) {
    return true;
  }

  // 2001:0000::/32 (Teredo - RFC 4380)
  if (words[0] === 0x2001 && words[1] === 0x0000) {
    // In Teredo, the last two words represent the XOR-negated client IPv4
    const v4Word1 = words[6] ^ 0xffff;
    const v4Word2 = words[7] ^ 0xffff;
    const embeddedIpv4 = `${(v4Word1 >>> 8) & 0xff}.${v4Word1 & 0xff}.${(v4Word2 >>> 8) & 0xff}.${v4Word2 & 0xff}`;
    if (isPrivateOrReservedIPv4(embeddedIpv4)) return true;
  }

  // 2001:2::/48 (Benchmarking - RFC 5180)
  if (words[0] === 0x2001 && words[1] === 0x0002) {
    return true;
  }

  // 2002::/16 (6to4 - RFC 3056): words[1] and words[2] encode an IPv4 address
  if (words[0] === 0x2002) {
    const embeddedIpv4 = `${(words[1] >>> 8) & 0xff}.${words[1] & 0xff}.${(words[2] >>> 8) & 0xff}.${words[2] & 0xff}`;
    return isPrivateOrReservedIPv4(embeddedIpv4);
  }

  // fc00::/7 (Unique Local Address - ULA / RFC 4193: fc00:: to fdff:ffff:...)
  if ((words[0] & 0xfe00) === 0xfc00) {
    return true;
  }

  // fe80::/10 (Link-Local Unicast - RFC 4291: fe80:: to febf:ffff:...)
  if ((words[0] & 0xffc0) === 0xfe80) {
    return true;
  }

  // ff00::/8 (Multicast - RFC 4291)
  if ((words[0] & 0xff00) === 0xff00) {
    return true;
  }

  return false;
}

/**
 * Universal IP validator: returns true if the IP is private, reserved, loopback,
 * link-local, multicast, or non-routable public destination.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip || typeof ip !== "string") return true;
  const trimmed = ip.trim();

  if (net.isIPv4(trimmed)) {
    return isPrivateOrReservedIPv4(trimmed);
  }
  if (net.isIPv6(trimmed)) {
    return isPrivateOrReservedIPv6(trimmed);
  }

  // Not a valid IP address
  return true;
}
