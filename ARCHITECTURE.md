# Mola — Architecture & System Design

This document details the architectural design, component boundaries, data flow pipelines, and runtime characteristics of Mola Web Auditor.

---

## 1. System Overview & Technology Stack

Mola is built as a high-performance, single-tenant or edge-deployable web auditing platform utilizing modern web primitives:

- **Framework**: Next.js 16 (App Router, Turbopack, React 19 Server & Client Components)
- **Styling**: Tailwind CSS v4 with custom design tokens (`globals.css`)
- **Runtime**: Node.js v18+ (tested on v20 & v24)
- **Execution Model**: 100% ephemeral in-memory processing with zero database requirements
- **Deployment Targets**: Antideploy container runtimes, Vercel, Docker, or self-hosted bare metal

```mermaid
graph TD
    Client[Browser UI / User] -->|POST /api/scan| Middleware[Edge Middleware / Nonce CSP]
    Middleware --> Route[app/api/scan/route.ts]
    
    subgraph Gatekeeper
        Route --> RateLimit[Trusted Client IP Rate Limiter]
        Route --> Concurrency[Global Concurrency Gate (Max 5)]
        Route --> InputGuard[4KB Body / URL Sanitizer]
    end
    
    subgraph Target Resolution & SSRF
        InputGuard --> UrlValidator[URL Validator (RFC 3986, Port 80/443)]
        UrlValidator --> DnsValidator[Bounded DNS Lookup & IP Range Filter]
        DnsValidator --> SocketDefense[Connection-Time DNS Rebinding Defense]
    end

    subgraph Data Acquisition
        SocketDefense --> HttpScanner[Streaming HTTP Inspector (2.5MB Cap, 5 Hops)]
        HttpScanner --> ContextFactory[AuditContext Factory]
        ContextFactory --> HtmlParser[DOM AST Parser]
    end

    subgraph Diagnostic Modules (11 Domains)
        ContextFactory --> ModHttp[1. HTTP & Infrastructure]
        ContextFactory --> ModSec[2. Security Headers]
        ContextFactory --> ModCookies[3. Cookie Attributes]
        ContextFactory --> ModTls[4. TLS Observations]
        ContextFactory --> ModMixed[5. Mixed Content]
        ContextFactory --> ModSeo[6. SEO & Headings]
        ContextFactory --> ModA11y[7. Accessibility]
        ContextFactory --> ModBP[8. Best Practices]
        ContextFactory --> ModTech[9. Technology Detection]
        ContextFactory --> ModSri[10. Resource Integrity]
        ContextFactory --> ModIframe[11. Iframe Safety]
    end

    subgraph Deep Scan Engine
        ContextFactory --> BrowserRunner[Isolated Browser Runner (Playwright/Chrome)]
    end

    subgraph Synthesis & Reporting
        ModHttp & ModSec & ModCookies & ModTls & ModMixed & ModSeo & ModA11y & ModBP & ModTech & ModSri & ModIframe & BrowserRunner --> Dedup[Semantic Deduplication Engine]
        Dedup --> Coverage[Coverage & Limitation Calculator]
        Coverage --> Comparator[Fix Verification Comparator]
        Comparator --> Formatter[ScanResult Envelope]
    end

    Formatter --> Route
    Route -->|JSON Payload| Client
    Client --> UI[Telemetry Dashboard & Export Studio]
```

---

## 2. Request & Execution Lifecycle

### Step 1: Client Request & Nonce-Based CSP
When the user accesses Mola, `middleware.ts` intercepts the request:
- Generates a cryptographically random UUID nonce per request (`crypto.randomUUID()`).
- Establishes a single authoritative `Content-Security-Policy` header using `'strict-dynamic'` and the per-request nonce.
- Forwards `x-nonce` to downstream Server Components (`app/layout.tsx`), which dynamically renders `<html lang="en">` with native Next.js script nonce injection.

### Step 2: Rate Limiting & Concurrency Control (`app/api/scan/route.ts`)
1. **Client Identity**: The API uses `extractClientIp()` to identify the client, prioritizing trusted proxy headers:
   - `CF-Connecting-IP` (Cloudflare)
   - `X-Real-IP` (Nginx/Traefik)
   - Leading entry from `X-Forwarded-For`
   - Fallback to loopback `127.0.0.1` for local runs
2. **Rate Limiting**: Enforces 15 requests per minute per IP via an in-memory sliding window.
3. **Concurrency Limiter**: Limits active simultaneous audits to 5 global scans to protect system resources.
4. **Request Body Bounds**: Accepts a maximum JSON payload of 4 KB.

### Step 3: URL & SSRF Validation (`server/validators/`)
Before any socket is opened:
- `validateUrlSyntax()` checks RFC 3986 compliance, scheme (`http:` / `https:`), and port restrictions (80 / 443).
- Embedded user credentials (`user:pass@host`) and single-label domain names are rejected.
- `resolveAndValidateDns()` resolves all A and AAAA records via a bounded DNS lookup (5-second timeout).
- `isPrivateOrBlockedIp()` validates every resolved IP address against RFC 1918, RFC 6598 (CGNAT), RFC 3927 (link-local), RFC 4291 (IPv6 unique local/link-local), IPv4-mapped IPv6, and cloud metadata (`169.254.169.254`).

### Step 4: Controlled HTTP Acquisition (`server/scanners/http.ts`)
The HTTP scanner initiates a controlled request:
- **Operation Deadline**: 15 seconds global execution ceiling.
- **Per-Hop Timeout**: 10 seconds per request socket.
- **Streaming Body Cap**: Reads up to 2.5 MB (2,621,440 bytes). If the response body exceeds this, the stream is cleanly destroyed (`stream.destroy()`) and marked `isTruncated: true`.
- **Hop-by-Hop Redirect Validation**: Follows up to 5 redirects manually (`redirect: "manual"`). Each redirect location header is resolved, verified against SSRF policies, and connection-bound before making the next hop.

### Step 5: Shared `AuditContext` Construction (`server/context.ts`)
A unified `AuditContext` is generated containing:
- `targetUrl`, `finalUrl`, `hostname`
- `httpInfo`: Status code, status text, TTFB latency, redirect chain, raw response headers
- `body`: Raw HTML text, byte length, truncation flag
- `dom`: Lightweight HTML DOM representation from `server/htmlParser.ts`
- `resources`: Discovered subresources (scripts, stylesheets, images, iframes)
- `technologyObservations`: Candidate technology markers
- `limitations`: Documented scan constraints

### Step 6: Diagnostic Module Execution (`server/modules/index.ts`)
Audit logic is partitioned into 11 decoupled domain modules:
1. **HTTP & Infrastructure**: TTFB latency benchmarks (<300ms, 300–800ms, >800ms), Brotli/Gzip compression, Cache-Control headers.
2. **Security Headers**: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server version leaks.
3. **Cookies**: Set-Cookie inspection for `Secure`, `HttpOnly`, `SameSite` flags, and cookie prefixes (`__Host-`, `__Secure-`).
4. **TLS Observations**: Plaintext HTTP usage vs encrypted HTTPS transport.
5. **Mixed Content**: Detection of active and passive unencrypted `http://` subresources loaded over HTTPS.
6. **SEO**: Document `<title>` presence and character limits, meta description length (50–160 chars), canonical URLs, heading hierarchy (`<h1>`).
7. **Accessibility (a11y)**: HTML document `lang` attribute, image `alt` attributes, form `<input>` label associations, duplicate DOM IDs.
8. **Best Practices**: HTML5 DOCTYPE, UTF-8 charset declarations, obsolete HTML tags (`<center>`, `<font>`, `<marquee>`, `<blink>`).
9. **Technology Detection**: High-confidence signatures for frontend frameworks, CDNs, and server engines without superficial substring false-positives.
10. **Resource Integrity (Deep)**: Subresource Integrity (`integrity`, `crossorigin`) on external third-party script tags.
11. **Iframe Safety (Deep)**: Iframe sandboxing (`sandbox`) and lazy loading (`loading="lazy"`).

### Step 7: Isolated Browser Deep Scan (`server/browser.ts`)
When Deep Scan mode is active:
- Validates browser runtime availability (Chromium executable or adapter).
- Applies strict navigation timeout (10 seconds) and SSRF-hardened navigation.
- Evaluates dynamically rendered DOM, runtime network resource observations, and JavaScript-rendered accessibility attributes.
- If browser execution is unavailable or unsupported in the current environment, reports an explicit limitation (`limitationReason`) rather than fabricating data.

### Step 8: Semantic Deduplication & Synthesis (`server/orchestrator.ts`)
- Findings are deduplicated using composite keys: `${category}:${ruleId}:${target}:${condition}`.
- True duplicates are merged while aggregating all distinct supporting evidence instances.
- Coverage metrics are computed (`server/coverage.ts`) differentiating attempted, completed, unable-to-check, and failed checks.

### Step 9: Fix Verification Comparison (`lib/compare.ts`)
When a rescan occurs on the same hostname:
- Compares previous scan findings with current scan findings.
- Classifies each baseline issue into 5 distinct states:
  - `fixed`: Verified resolved with direct negative evidence.
  - `still_present`: Issue continues to persist.
  - `changed`: Condition changed in severity, confidence, or material details.
  - `new`: Newly introduced defect not present in baseline.
  - `unable_to_verify`: Baseline issue could not be evaluated due to scanner limitation or host failure.

---

## 3. Directory Layout & Module Responsibilities

```text
app/
├── api/scan/route.ts        # Rate-limited, concurrency-guarded API route handler
├── components/              # Clean UI component library
│   ├── ExportControls.tsx   # Markdown (issues.md) and JSON export actions
│   ├── FindingFilters.tsx   # Keyword search, severity, and category filtering
│   ├── FindingItem.tsx      # Ordered finding card with 6-question evidence hierarchy
│   ├── FindingList.tsx      # Feed container, raw headers explorer, passing checks
│   ├── HeroSection.tsx      # Target URL input, scan mode toggle, audit trigger
│   ├── ReportSummary.tsx    # Target metadata, severity metrics, coverage badges
│   ├── ScanProgress.tsx     # Authentic operational stage progress tracker
│   └── VerificationSection.tsx # 5-way Fix Verification diff visualizer
├── globals.css              # Custom styling tokens and Tailwind CSS v4 variables
├── layout.tsx               # Root layout with dynamic nonce header consumption
├── page.tsx                 # Main application page & session audit orchestration
├── privacy/page.tsx         # Privacy Policy documentation
└── terms/page.tsx           # Terms of Service & acceptable use guidelines

server/
├── browser.ts               # Isolated browser runner adapter & runtime checks
├── context.ts               # AuditContext construction & resource discovery
├── coverage.ts              # Deterministic check coverage & limitation tracking
├── evidenceEngine.ts        # Reusable evidence formatting & 6-question constructors
├── htmlParser.ts            # Lightweight DOM AST parser
├── orchestrator.ts          # Central scan pipeline & verification execution
├── modules/                 # 11 domain audit modules (HTTP, Security, SEO, etc.)
├── scanners/                # Modular scanners (http, security, seo, a11y, tech, deep)
└── validators/              # Security validators (url, ip, dns)

lib/
├── compare.ts               # Semantic 5-state audit comparison engine
├── exportJson.ts            # JSON serialization and browser download trigger
└── exportMarkdown.ts        # LLM-ready issues.md report generator

types/
└── audit.ts                 # Authoritative TypeScript types and schemas
```
