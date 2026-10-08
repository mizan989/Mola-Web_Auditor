# Mola — Engineering & Architecture Rules

This document establishes the non-negotiable engineering principles, development rules, and quality standards for the Mola Web Auditor codebase. Every contributor, maintainer, and automated coding agent must adhere strictly to these rules without exception.

---

## 1. Core Product & Architectural Rules

### Rule 1.1: Zero Arbitrary Vanity Scores
- **Never calculate or display a synthetic 0–100% aggregate score**, quality percentage, health index, or letter grade.
- Audits must evaluate technical criteria independently.
- Findings are classified by **State** (`confirmed`, `not_detected`, `unable_to_check`, `failed`, `observation`, `recommendation`), independent **Severity** (`critical`, `high`, `medium`, `low`, `info`), and **Confidence** (`high`, `medium`, `low`).

### Rule 1.2: First-Class Truthful Evidence
- Every emitted finding must answer the **Six Core Questions**:
  1. **What was observed**: Concrete raw evidence string, header value, or DOM snippet.
  2. **Where**: Exact location (URL, header name, or CSS selector).
  3. **How observed**: Detection method (`header-inspection`, `dom-parsing`, `rendered-dom`, `network-stream`, etc.).
  4. **Why it matters**: Specific real-world security, performance, or SEO implications.
  5. **What limitation exists**: Explicit scope boundaries or partial visibility caveats.
  6. **What to do**: Actionable developer remediation instructions with production-ready code snippets.
- Speculative or heuristic observations must be marked as `medium` or `low` confidence, or state `observation`, never a confirmed critical flaw.

### Rule 1.3: Transparent Coverage & Limitations
- Never conflate **"not found"** (clean pass) with **"not checked"** (unsupported or blocked).
- If a check cannot be executed (due to network timeout, bot block, or headless restrictions), it must be recorded as `unable_to_check` or a documented limitation.
- Never fabricate scan coverage percentages without a rigorous deterministic methodology.

---

## 2. Security & Network Defense Rules

### Rule 2.1: Defense-in-Depth SSRF Prevention
- Strict URL validation according to RFC 3986.
- Protocols permitted: `http:` and `https:` exclusively.
- Ports permitted: `80` and `443` exclusively.
- Sockets must **never** be established to:
  - Loopback (`127.0.0.0/8`, `::1`)
  - Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Carrier-Grade NAT (`100.64.0.0/10`)
  - Link-local and cloud metadata (`169.254.0.0/16`, `fe80::/10`)
  - IPv6 Unique Local Addresses (`fc00::/7`)
  - IPv4-mapped IPv6 ranges (`::ffff:0:0/96`)
  - Internal/reserved suffixes (`.local`, `.internal`, `.corp`, etc.)

### Rule 2.2: Connection-Time DNS Rebinding Defense
- Hostname validation at URL parse time is **not sufficient**.
- Sockets must be validated at connection time via custom agent socket hooks or safe resolver pinning to guarantee the IP connected matches the validated public IP.
- DNS resolution must have bounded timeouts (default 5,000ms) integrated into the operation deadline.

### Rule 2.3: Hop-by-Hop Redirect Validation
- Redirects must be handled manually, hop-by-hop.
- Maximum redirect limit is strictly capped at **5 hops**.
- Every single redirect destination must be re-validated through the full SSRF and DNS pipeline before establishing a new socket.

### Rule 2.4: Bounded Resource Consumption
- **Response Body Cap**: Strictly capped at **2.5 MB** (2,621,440 bytes). Streams exceeding this limit must be cleanly truncated, releasing sockets immediately.
- **Scan Deadline**: Global operation timeout of **15 seconds**.
- **Per-Hop Timeout**: Maximum socket timeout of **10 seconds** per request.
- **Request Body Cap**: API requests capped at **4 KB**.
- **Rate Limiting**: 15 requests per minute per IP using trusted proxy headers (`CF-Connecting-IP`, `X-Real-IP`).
- **Concurrent Active Scans**: Maximum **5 concurrent scans** globally.

---

## 3. Ephemeral Execution & Privacy Rules

### Rule 3.1: Zero Database Persistence
- Mola operates 100% statelessly in volatile RAM.
- Audit results and target URLs are never stored in a server database or persistent disk storage.
- Memory allocations must be garbage-collected immediately upon request completion.

### Rule 3.2: Error Sanitization
- Internal server error messages must never leak filesystem paths, stack traces, internal IPs, or environment details to the client.
- Status codes:
  - `400 Bad Request`: SSRF policy violation or invalid input.
  - `502 Bad Gateway`: Target host unreachable or DNS failure.
  - `504 Gateway Timeout`: Scan deadline or connection timeout exceeded.
  - `429 Too Many Requests`: Rate limit or concurrency limit exceeded.

---

## 4. Content Security & UI Guidelines

### Rule 4.1: Single Authoritative Nonce-Based CSP
- Content-Security-Policy must be defined dynamically in `middleware.ts` with per-request cryptographic nonces and `strict-dynamic`.
- Do not retain static conflicting CSP headers in `next.config.ts`.
- Do not allow `'unsafe-inline'` scripts.

### Rule 4.2: Strict Accessibility (a11y) & Interactive Hygiene
- **Never nest interactive elements**: No `<button>` inside `<button>`, no `<a>` inside `<button>`.
- Interactive cards must use appropriate ARIA roles (`role="button"`, `tabIndex={0}`, keyboard handlers).
- Form inputs must have accessible labels (`htmlFor`, `aria-label`).
- Severity must be communicated through text and icons, never color alone.

---

## 5. Phase-Gating Development Lifecycle

When upgrading or modifying Mola:
1. **Inspect Before Editing**: Treat the current codebase as source of truth.
2. **Never Weaken Security**: Never disable or soften security checks to make tests pass.
3. **No External Dependencies**: Avoid adding unvetted third-party npm packages.
4. **Mandatory Verification Gate**:
   - `npm test` (all tests must pass)
   - `npm run typecheck` (0 TypeScript errors)
   - `npm run lint` (0 ESLint errors or warnings)
   - `npm run build` (Next.js production build succeeds)
