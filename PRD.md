# Mola — Product Requirements Document (PRD)

## 1. Product Overview
**Mola** is an open-source, evidence-based web auditor built for developers and engineering teams. Unlike legacy audit tools that generate arbitrary percentage vanity scores or unverified recommendations, Mola operates as an evidence-first diagnostic platform. Every finding is backed by cryptographic or structural observations, concrete provenance, and actionable remediation steps.

---

## 2. Core Philosophy & Product Principles
1. **Evidence First, Zero Vanity Scores**: No arbitrary 0-100% numeric scores. Findings are classified by state, independent impact severity, and certainty confidence.
2. **Deterministic & Verifiable**: Results must be reproducible. Observations link directly to headers, DOM nodes, cookies, or network responses.
3. **Defense-in-Depth Security**: Strict SSRF prevention at both URL parsing time and actual socket establishment time (connection-time DNS rebinding defense).
4. **Transparent Limitations**: If a check cannot be executed (e.g., due to bot protection, network timeout, or headless restrictions), it is explicitly categorized as `unable_to_check` or a documented limitation, never a false pass.

---

## 3. Functional Requirements (FR)

### FR-001: Target Validation & SSRF Prevention
- Enforce strict URL format validation conforming to RFC 3986.
- Restrict transport protocols exclusively to `http://` and `https://`.
- Restrict network ports exclusively to standard web ports `80` and `443`.
- Deny loopback (`127.0.0.0/8`, `::1`), private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Carrier-Grade NAT (`100.64.0.0/10`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), unique-local IPv6 (`fc00::/7`), IPv4-mapped IPv6, and internal/reserved suffixes (`.local`, `.internal`, `.corp`, etc.).
- Prevent DNS rebinding at socket connection time via connection-time IP validation interceptors.
- Validate every redirect destination hop individually before establishing sockets (max 5 hops).

### FR-002: Dual Audit Scan Modes
- **Quick Scan**: Lightweight, high-throughput server-side HTTP/TLS inspection utilizing bounded streaming (2.5MB cap) and an operation deadline of 15 seconds.
- **Deep Scan**: Headless browser execution utilizing sandboxed Chromium to render client-side JavaScript, observe dynamically injected subresources, evaluate rendered DOM accessibility, and detect runtime mixed content.

### FR-003: Audit Modules & Rule Coverage
Mola organizes audits into 11 specialized diagnostic modules:
1. **HTTP & Infrastructure**: TTFB latency, Gzip/Brotli compression, Cache-Control declarations, body bounds.
2. **Security Headers**: Strict CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server version leaks.
3. **Cookies**: Flags (`Secure`, `HttpOnly`, `SameSite=Strict|Lax`), prefix enforcement (`__Host-`, `__Secure-`).
4. **TLS Observations**: Plaintext HTTP detection, HTTPS transport enforcement, TLS version observation.
5. **Mixed Content**: Passive and active HTTP subresources loaded on HTTPS pages.
6. **SEO**: Document title, meta description length, canonical links, heading hierarchy (`<h1>`).
7. **Accessibility (a11y)**: HTML document language (`lang`), image alternative text (`alt`), input label associations, duplicate IDs.
8. **Best Practices**: HTML5 doctype, UTF-8 charset declarations, deprecated HTML tags.
9. **Technology Detection**: Verifiable signatures for frameworks (Next.js, React, Tailwind CSS, etc.) without superficial substring false-positives.
10. **Resource Integrity**: Subresource Integrity (`integrity`, `crossorigin`) for third-party scripts.
11. **Iframe Safety**: Sandbox attributes and lazy loading (`loading="lazy"`).

### FR-004: First-Class Evidence Engine
Every emitted finding must address the Six Core Questions:
- **What was observed**: Concrete raw evidence string or header value.
- **Where**: Affected target URL, header, or CSS selector.
- **How observed**: Detection mechanism (`header-inspection`, `dom-parsing`, `rendered-dom`, `network-stream`, etc.).
- **Why it matters**: Real-world security, performance, or SEO implications.
- **What limitation exists**: Explicit scope boundaries or partial visibility caveats.
- **What to do**: Actionable developer remediation instructions.

### FR-005: Severity & Confidence Decoupling
- **Severity** reflects the impact if the condition is true: `critical`, `high`, `medium`, `low`, `info`.
- **Confidence** reflects the certainty that the condition is present: `high`, `medium`, `low`.
- Findings with indirect or speculative evidence must be marked as `medium` or `low` confidence.

### FR-006: Semantic Deduplication & Group Correlation
- Correlate audit observations using deterministic composite keys: `${category}:${ruleId}:${target}:${condition}`.
- Prevent duplicate findings while preserving all distinct supporting evidence instances.

### FR-007: Verification & Audit Comparison Engine
- Enable diffing a previous audit against a current audit.
- Classify findings into 5 verified delta states:
  - `fixed`: Previously identified issue successfully resolved.
  - `still_present`: Issue continues to persist.
  - `changed`: Condition changed in severity, confidence, or material details.
  - `new`: Newly discovered issue not present in the baseline.
  - `unable_to_verify`: Baseline issue could not be evaluated due to scanner or connection failure.

### FR-008: Lossless Export
- **Markdown Export**: Human-readable, structured executive report preserving all evidence fields and surface reconnaissance.
- **JSON Export**: Machine-readable schema preserving complete typed finding envelopes, telemetry, and limitations for CI/CD integration.

### FR-009: Audit Coverage & Limitation Tracking
- Track attempted checks, completed checks, unable-to-check checks, failed checks, and scan limitations.
- Clearly differentiate "not found" (passed) from "not checked" (unsupported or blocked).

### FR-010: Release & Security Hardening
- Enforce strict per-request Content-Security-Policy with cryptographic nonces (`strict-dynamic`).
- Limit scan concurrency and enforce client rate limiting based on trusted proxy headers (`CF-Connecting-IP`, `X-Real-IP`).
- Sanitize backend exceptions to prevent internal filesystem or stack trace leakage.
