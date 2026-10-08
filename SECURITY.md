# Mola — Security Policy & Threat Model

This document outlines the security architecture, threat model, protective controls, and vulnerability reporting process for Mola Web Auditor.

---

## 1. Vulnerability Reporting

If you discover a potential security vulnerability in Mola, please report it responsibly:

- **Email**: Reach out to the maintainer directly via GitHub ([@mizan989](https://github.com/mizan989)).
- **Scope**: Please do not open public GitHub issues for undisclosed security vulnerabilities. Provide a description of the issue, reproduction steps, and potential impact.
- **Response Target**: We aim to acknowledge receipt within 48 hours and provide a fix or mitigation timeline within 7 days.

---

## 2. Threat Model & Risk Vectors

Because Mola accepts arbitrary URLs from users and fetches remote web assets, the platform operates against an active threat landscape:

| Threat Vector | Description | Potential Impact |
|---|---|---|
| **SSRF to Private Networks** | Attacker specifies internal RFC 1918 IP addresses (`10.0.0.0/8`, `192.168.0.0/16`, etc.) | Scanning of local intranet or internal services |
| **Cloud Metadata Theft** | Attacker specifies link-local metadata endpoints (`169.254.169.254`) | Leakage of IAM tokens or instance credentials |
| **DNS Rebinding Attack** | Attacker configures dual DNS records returning a public IP first, followed by a loopback IP | Bypassing pre-flight URL validation to access local host |
| **Malicious Redirects** | Initial public URL returns a `302 Found` pointing to `http://localhost/` or internal APIs | Escaping initial validation via unmonitored redirect traversal |
| **Slowloris / Resource Starvation** | Remote host responds with infinite, slow, or gigabyte-sized payloads | Memory exhaustion, connection pool exhaustion, DoS |
| **Redirect Loop / Fork Bomb** | Remote host returns recursive or cyclic HTTP redirects | Thread blocking, infinite loop exhaustion |
| **Client-Side XSS via Audit Data** | Malicious site injects `<script>` payloads into `<title>` or HTTP headers | Execution of unauthorized JavaScript in the user's browser |
| **Information Leakage via Errors** | Backend crashes or exposes internal file paths and stack traces | Reconnaissance data leak to untrusted clients |

---

## 3. Defense-in-Depth Security Controls

Mola implements eight defensive layers to completely neutralize these threats:

### Layer 1: Strict URL Parsing & Protocol/Port Allowlisting
- **Implementation**: [`server/validators/url.ts`](server/validators/url.ts)
- **Controls**:
  - Restricts schemes strictly to `http:` and `https:`. All other schemes (`file:`, `ftp:`, `gopher:`, `data:`, `javascript:`) are rejected.
  - Restricts destination ports strictly to standard web ports: `80` and `443`.
  - Rejects URLs with embedded credentials (`user:pass@host`).
  - Rejects single-label domain names lacking a public top-level domain.
  - Rejects internal and reserved TLD suffixes (`.local`, `.internal`, `.lan`, `.corp`, `.home`, `.test`, `.example`, `.invalid`, `.localhost`).

### Layer 2: Multi-Record DNS Validation & Comprehensive Subnet Filtering
- **Implementation**: [`server/validators/dns.ts`](server/validators/dns.ts), [`server/validators/ip.ts`](server/validators/ip.ts)
- **Controls**:
  - Resolves all A and AAAA records using `dns.lookup(hostname, { all: true })` with an integrated 5-second operation timeout.
  - Evaluates every resolved address against exhaustive blocked ranges:
    - `127.0.0.0/8` (IPv4 Loopback)
    - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private Subnets)
    - `100.64.0.0/10` (Carrier-Grade NAT)
    - `169.254.0.0/16` (Link-Local / Cloud Instance Metadata)
    - `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (TEST-NET / IETF Protocol Assignments)
    - `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32` (Multicast / Reserved / Broadcast)
    - `::1/128` (IPv6 Loopback)
    - `fc00::/7` (IPv6 Unique Local Address)
    - `fe80::/10` (IPv6 Link-Local Unicast)
    - `ff00::/8` (IPv6 Multicast)
    - `::ffff:0:0/96` (IPv4-Mapped IPv6 Addresses)

### Layer 3: Connection-Time DNS Rebinding Defense
- **Implementation**: [`server/validators/dns.ts`](server/validators/dns.ts), [`server/scanners/http.ts`](server/scanners/http.ts)
- **Controls**:
  - Prevents Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
  - Socket establishment interceptor guarantees the IP address actually connected during the socket handshake matches the pre-validated public IP address.
  - Any connection attempting to resolve or connect to a prohibited IP at socket establishment time is immediately terminated.

### Layer 4: Hop-by-Hop Redirect Validation
- **Implementation**: [`server/scanners/http.ts`](server/scanners/http.ts)
- **Controls**:
  - HTTP client specifies `redirect: "manual"` to intercept every redirect step.
  - Maximum redirect depth is strictly bounded to **5 hops**.
  - Every redirect target URL is parsed, normalized, and validated through the full URL and SSRF pipeline before the subsequent socket is created.
  - Redirect loops (e.g., A → B → A) are detected and aborted immediately.

### Layer 5: Strict Resource Ceilings & Bounded Streaming
- **Implementation**: [`server/scanners/http.ts`](server/scanners/http.ts), [`server/orchestrator.ts`](server/orchestrator.ts)
- **Controls**:
  - **Body Payload Cap**: Exactly **2.5 MB** (2,621,440 bytes). Responses exceeding this limit are terminated mid-stream, destroying the underlying socket without loading excess bytes into memory.
  - **Global Scan Deadline**: Maximum **15 seconds** total execution window per audit.
  - **Per-Hop Timeout**: Maximum **10 seconds** per individual HTTP request.
  - **Request Body Boundary**: POST bodies to `/api/scan` are capped at **4 KB**.

### Layer 6: Reverse-Proxy Rate Limiting & Concurrency Controls
- **Implementation**: [`app/api/scan/route.ts`](app/api/scan/route.ts)
- **Controls**:
  - Extracts authentic client IP using `extractClientIp()`, prioritizing reverse-proxy headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`).
  - Sliding-window rate limit: **15 requests per minute** per client IP.
  - Concurrency gate: Maximum **5 active concurrent scans** across the entire node process. Excess requests receive `429 Too Many Requests`.

### Layer 7: Authoritative Content Security Policy (CSP)
- **Implementation**: [`middleware.ts`](middleware.ts), [`app/layout.tsx`](app/layout.tsx)
- **Controls**:
  - Emits a dynamic, single authoritative Content Security Policy from Next.js middleware with per-request cryptographic nonces (`'nonce-${nonce}'`).
  - Implements `'strict-dynamic'` for modern script execution.
  - Completely disallows `'unsafe-inline'` script execution.
  - Blocks framing (`frame-ancestors 'none'`) and object plugins (`object-src 'none'`).

### Layer 8: Safe Error Sanitization
- **Implementation**: [`app/api/scan/route.ts`](app/api/scan/route.ts)
- **Controls**:
  - Internal exceptions are categorized and mapped to generic, safe developer error messages.
  - Raw filesystem paths, operating system details, internal socket error traces, and stack traces are strictly stripped before returning JSON responses.

---

## 4. Adversarial Test Coverage

The security controls are validated by an extensive adversarial automated test suite ([`tests/security-architecture.test.ts`](tests/security-architecture.test.ts)):

1. **Localhost & Loopback Probing**: Rejection of `127.0.0.1`, `localhost`, `127.127.127.127`, `::1`.
2. **Private Network Traversal**: Rejection of `10.0.0.1`, `172.16.0.1`, `192.168.1.1`, `100.64.0.1`.
3. **Cloud Metadata Exfiltration**: Rejection of `169.254.169.254`, `http://169.254.169.254/latest/meta-data/`.
4. **IPv6 Mapped & ULA**: Rejection of `::ffff:127.0.0.1`, `fc00::1`, `fe80::1`.
5. **Redirect Escapes**: Tests verifying redirect destinations pointing to loopback or private ranges are blocked at the hop.
6. **DNS Rebinding**: Bounded DNS timeouts and socket-level IP binding.
7. **Resource Limits**: Enforcement of the 2.5 MB payload cap and 15-second operation deadline.
