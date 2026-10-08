# Mola — Issue Resolution & Upgrade Ledger

This document serves as the permanent historical ledger of all addressed engineering issues, security hardening tasks, architectural enhancements, and quality improvements across Mola Web Auditor.

---

## Issue Ledger Summary

| Issue ID | Domain | Summary | Status |
|---|---|---|---|
| **ISSUE-001** | Security | Strict RFC 3986 URL syntax, protocol (`http:`, `https:`), and port (80, 443) validation | **Resolved** |
| **ISSUE-002** | Security | Rejection of URLs with embedded user credentials (`user:pass@host`) | **Resolved** |
| **ISSUE-003** | Security | Comprehensive IP range validation blocking RFC 1918, CGNAT, link-local, metadata, and IPv6 ULA | **Resolved** |
| **ISSUE-004** | Security | Multi-record DNS resolution and anti-rebinding IP filtering | **Resolved** |
| **ISSUE-005** | Security | Client IP extraction from trusted proxy headers (`CF-Connecting-IP`, `X-Real-IP`) and rate limiting | **Resolved** |
| **ISSUE-006** | Reliability | Global active scan concurrency limiting (max 5 simultaneous scans) | **Resolved** |
| **ISSUE-007** | Security | Maximum POST request body size enforcement (4 KB cap) | **Resolved** |
| **ISSUE-008** | Security | Backend error sanitization preventing filesystem path and stack trace leakage | **Resolved** |
| **ISSUE-009** | Architecture | Scan mode decoupling: Quick Scan (fast headers/HTML) vs Deep Scan (assets/browser) | **Resolved** |
| **ISSUE-010** | Telemetry | Accurate HTTP protocol version observation without synthetic assumptions | **Resolved** |
| **ISSUE-011** | Performance | Microsecond-accurate Time-To-First-Byte (TTFB) latency measurement | **Resolved** |
| **ISSUE-012** | Reliability | Bounded streaming body fetch with 2.5 MB ceiling to prevent memory exhaustion | **Resolved** |
| **ISSUE-013** | Reliability | Global operation deadline (15s) and per-hop socket timeout (10s) enforcement | **Resolved** |
| **ISSUE-014** | Security | Hop-by-hop redirect traversal with SSRF validation at every hop (max 5 hops) | **Resolved** |
| **ISSUE-015** | Discovery | High-confidence framework detection without loose substring false-positives (Next.js, React) | **Resolved** |
| **ISSUE-016** | Discovery | Tailwind CSS detection via stylesheet URLs and high-confidence class clusters | **Resolved** |
| **ISSUE-017** | Security | Security headers audit (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy) | **Resolved** |
| **ISSUE-018** | Security | Cookie security audit (`Secure`, `HttpOnly`, `SameSite`, prefix enforcement) | **Resolved** |
| **ISSUE-019** | Security | Insecure mixed content detection across active and passive subresources on HTTPS | **Resolved** |
| **ISSUE-020** | Accessibility | Image alternative text (`alt`) audit surfacing exact element snippets | **Resolved** |
| **ISSUE-021** | Accessibility | Form `<input>` accessible labeling verification and duplicate DOM ID detection | **Resolved** |
| **ISSUE-022** | SEO | Search indexing audit: `<title>` length, meta description, canonical URLs, `<h1>` hierarchy | **Resolved** |
| **ISSUE-023** | Security | Subresource Integrity (SRI) audit on external third-party `<script>` tags | **Resolved** |
| **ISSUE-024** | UI/UX | Tab session storage persistence allowing seamless rescan comparison | **Resolved** |
| **ISSUE-025** | Verification | Semantic finding comparison engine comparing successive scan runs | **Resolved** |
| **ISSUE-026** | UI/UX | Removal of fabricated progress bars and fake timers; authentic indeterminate stages | **Resolved** |
| **ISSUE-027** | Product | Elimination of arbitrary 0–100% vanity scores in favor of independent severity tiers | **Resolved** |
| **ISSUE-028** | Transparency | Clear distinction between complete scans and partial scans with payload truncation alerts | **Resolved** |
| **ISSUE-029** | Architecture | Standardized 6-question concrete evidence formatting for all findings | **Resolved** |
| **ISSUE-030** | Architecture | Decoupling of severity (real-world impact) and confidence (certainty of observation) | **Resolved** |
| **ISSUE-031** | Architecture | Lightweight DOM AST parser (`htmlParser.ts`) replacing brittle regular expressions | **Resolved** |
| **ISSUE-032** | Architecture | Shared server-side `AuditContext` eliminating redundant remote network requests | **Resolved** |
| **ISSUE-033** | Discovery | Subresource tracking and surface reconnaissance layer | **Resolved** |
| **ISSUE-034** | Security | Cryptographic UUID generation via standard `crypto.randomUUID()` | **Resolved** |
| **ISSUE-035** | UI/UX | Non-disruptive polite inline toast notifications replacing intrusive browser `alert()` | **Resolved** |
| **ISSUE-036** | Architecture | Candidate detection vs evidence validation separation across all audit rules | **Resolved** |
| **ISSUE-037** | Architecture | Semantic finding deduplication using deterministic composite keys | **Resolved** |
| **ISSUE-038** | Architecture | Isolated browser Deep Scan execution with runtime checks and explicit limitation reporting | **Resolved** |
| **ISSUE-039** | Verification | 5-state fix verification classification (`fixed`, `still_present`, `changed`, `new`, `unable_to_verify`) | **Resolved** |
| **ISSUE-040** | Coverage | Deterministic check coverage accounting differentiating "not found" from "not checked" | **Resolved** |
| **ISSUE-041** | Security | Socket-level connection-time DNS rebinding defense | **Resolved** |
| **ISSUE-042** | Reliability | Bounded DNS lookup timeout (5s) integrated into operation-level scan deadline | **Resolved** |
| **ISSUE-043** | UI/UX | Hero section visual simplification: removal of redundant pill badge | **Resolved** |
| **ISSUE-044** | UI/UX | Removal of hardcoded presets row in favor of clean developer URL input | **Resolved** |
| **ISSUE-045** | UI/UX | Report summary hierarchy refinement with responsive telemetry cards | **Resolved** |
| **ISSUE-046** | UI/UX | Finding card readability ordering: severity → title → description → evidence → impact → fix | **Resolved** |
| **ISSUE-047** | Accessibility | Accessible severity indicators pairing visible text, distinct icons, and ARIA labels | **Resolved** |
| **ISSUE-048** | UI/UX | Integrated finding filter bar with keyword search, category, severity, and Clear Filters action | **Resolved** |
| **ISSUE-049** | Export | AI-ready `issues.md` Markdown generation and machine-readable JSON export studio | **Resolved** |
| **ISSUE-050** | Verification | Verification diff section highlighting resolved, remaining, changed, and new issues | **Resolved** |

---

## Detailed Notes on Key Resolutions

### SSRF & DNS Rebinding (ISSUE-001, ISSUE-003, ISSUE-004, ISSUE-041, ISSUE-042)
Target validation operates in three stages:
1. Syntax and protocol validation (`server/validators/url.ts`) restricts targets to `http://` and `https://` on ports `80` and `443`, immediately rejecting IP literals, internal suffixes, and credentials.
2. Multi-record DNS resolution (`server/validators/dns.ts`) resolves all A/AAAA records with a 5,000ms bounded timeout, validating that no resolved IP falls within RFC 1918, CGNAT, link-local, cloud metadata, or IPv6 unique-local ranges.
3. Socket connection binding intercepts the socket handshake to verify that the remote IP connected matches the validated IP address, neutralizing TOCTOU DNS rebinding.

### Bounded Streaming & Truncated Lifecycles (ISSUE-012, ISSUE-013)
The HTTP engine (`server/scanners/http.ts`) streams incoming responses through a byte-counting transformer capped at 2,621,440 bytes (2.5 MB). When an oversized payload arrives, the response stream is destroyed immediately, sockets are closed, and `isTruncated: true` is flagged, preventing server memory bloat while preserving all content read up to the threshold.

### Fix Verification Taxonomy (ISSUE-025, ISSUE-039, ISSUE-050)
The comparison engine (`lib/compare.ts`) compares findings using composite keys `${category}:${ruleId}:${target}:${condition}`:
- A finding is marked `fixed` only when direct positive evidence proves it is resolved.
- If a check could not run due to an unreachable host or scan limit, it is classified as `unable_to_verify` rather than falsely marked resolved.
- Diffs distinguish between unchanged persistence (`still_present`), severity/recommendation shifts (`changed`), and regressions (`new`).
