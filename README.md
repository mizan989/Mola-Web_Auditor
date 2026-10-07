<p align="center">
  <a href="https://mola.antideploy.app">
    <img src="./assets/logo.png" alt="Mola Logo" width="100" height="100">
  </a>
</p>

<div align="center">

# Mola

### The open-source evidence-based web auditing & telemetry engine for developers. Non-destructive URL inspection, security header analysis, and deterministic finding correlation with AI-ready `issues.md` exports.

<br/>

<a href="#-quick-start"><img src="https://img.shields.io/badge/Docs-Quickstart-06141B?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://mola.antideploy.app"><img src="https://img.shields.io/badge/Website-Mola-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
<a href="https://github.com/mizan989/Mola-Web_Auditor/discussions"><img src="https://img.shields.io/badge/Community-Discussions-06141B?style=for-the-badge&logo=github&logoColor=white" alt="Discussions"></a>

<a href="#-ways-to-run-mola"><img src="https://img.shields.io/badge/Mola%20App-Next.js%2016%20%2B%20React%2019-06141B?style=for-the-badge&logoColor=white" alt="Mola App"></a>
<a href="https://mola.antideploy.app"><img src="https://img.shields.io/badge/Try%20Live%20Demo-253745?style=for-the-badge&logoColor=white" alt="Try Live Demo"></a>

<a href="https://github.com/mizan989/Mola-Web_Auditor/stargazers"><img src="https://img.shields.io/github/stars/mizan989/Mola-Web_Auditor?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-3b82f6?style=flat-square" alt="License"></a>
<a href="https://nextjs.org"><img src="https://img.shields.io/badge/Next.js-16.3-black?style=flat-square&logo=next.js" alt="Next.js"></a>
<a href="https://react.dev"><img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React 19"></a>
<a href="https://www.typescriptlang.org"><img src="https://img.shields.io/badge/TypeScript-5.0-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>
<a href="https://tailwindcss.com"><img src="https://img.shields.io/badge/Tailwind-CSS%20v4-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white" alt="Tailwind CSS"></a>
<a href="https://antideploy.com"><img src="https://img.shields.io/badge/Deployed%20on-Antideploy-38B2AC?style=flat-square" alt="Antideploy"></a>

</div>

> [!TIP]
> **Live Web Auditor Ready!** Audit any public website live at **[mola.antideploy.app](https://mola.antideploy.app)** to receive concrete evidence, HTTP telemetry, and one-click `issues.md` exports for AI coding assistants (Gemini, Claude, Cursor) — [Get started locally in under 60 seconds](#-quick-start).

---

## Mola Overview

Mola is an open-source, evidence-first web auditing engine built for developers who want a fast, understandable, and reproducible way to diagnose issues across any website. Rather than overwhelming engineers with arbitrary vanity scores, decorative 0–100 rings, or opaque black-box recommendations, Mola surfaces concrete technical observations: raw response headers, observed element tags, measured network timings, and prioritized code remediation snippets.

Every finding explains what was detected, displays the exact evidence, identifies the affected element or header, clarifies why it matters, and provides an actionable code snippet to fix it.

$$\text{Enter URL} \longrightarrow \text{Validate SSRF} \longrightarrow \text{Inspect Telemetry} \longrightarrow \text{Audit Engines} \longrightarrow \text{Export issues.md} \longrightarrow \text{Verify Fix}$$

**Key Capabilities:**

- **Evidence-First Technical Reporting** — Every audit finding includes raw observed evidence, response headers, or affected DOM snippets rather than speculative assumptions
- **Zero Vanity Scores** — Replaces arbitrary percentage scores with ranked, actionable engineering priorities (`High`, `Medium`, `Low`, and `Fix First`)
- **Deep HTTP & Infrastructure Telemetry** — Inspects TTFB latency, TLS protocols, HTTP compression (Brotli/Gzip/Zstandard), redirect chains, and server headers
- **Automated Technology Fingerprinting** — Detects underlying frameworks (Next.js, React, Vue, Nuxt), CDNs (Cloudflare, Vercel, Netlify), and CMS engines
- **AI-Ready `issues.md` Artifact Generation** — One-click download or copy of structured Markdown reports specifically engineered to prompt AI coding agents (Gemini, Claude, Cursor, Copilot)
- **Fix Verification & Rescan Diffing** — Re-auditing a site compares subsequent scan runs against previous baselines, clearly segregating `🟢 Resolved`, `🟡 Remaining`, and `🔴 New Issues`
- **SSRF-Hardened Network Architecture** — Built-in RFC 1918 private IP range blocking, loopback mitigation, cloud metadata (`169.254.169.254`) isolation, and domain guardrails
- **100% Stateless & Private** — Pure ephemeral in-memory scan processing; zero database storage, zero tracking cookies, and zero persistent URL logging
- **Quiet Developer Aesthetic** — Minimalist editorial layout, high-contrast typography, and full-viewport section views optimized for desktop and mobile

<br>

<div align="center">
  <pre>
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                     MOLA                                        │
│        Target Input ➔ SSRF Validation ➔ HTTP Telemetry ➔ Audit Engines          │
├───────────────────────────────┬─────────────────────────────────────────────────┤
│  🛡️ Security Header Engine    │  ⚡ Performance & Asset Engine                   │
│   • CSP, HSTS, X-Frame-Options│    • TTFB Latency Benchmark                     │
│   • Referrer & Permissions    │    • Compression (Brotli/Gzip)                  │
│   • Version Banner Leakage    │    • Render-blocking scripts                    │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│  🔍 SEO & Heading Hierarchy   │  ♿ Accessibility (a11y) Verification            │
│   • Title, Meta Description   │    • Image alt completeness                     │
│   • OpenGraph & Canonical     │    • HTML lang attribute                        │
│   • Heading levels (h1-h6)    │    • Semantic landmark navigation               │
├───────────────────────────────┼─────────────────────────────────────────────────┤
│  📊 Technology Detection      │  🔁 Fix Verification & Export                   │
│   • Frameworks (Next/React)   │    • issues.md Markdown Export                  │
│   • CMS (WordPress/Shopify)   │    • Structured JSON Export                     │
│   • CDN & Edge Servers        │    • Before/After Fix Verification Loop         │
└───────────────────────────────┴─────────────────────────────────────────────────┘
  </pre>
</div>

---

## UI Preview

<p align="center">
  <img src="./assets/screenshot1.png" alt="Mola Web Auditor - Instant Audit Scanner & Presets" width="100%" />
</p>

<br/>

<p align="center">
  <img src="./assets/screenshot2.png" alt="Mola Web Auditor - Deep Evidence Telemetry, Technology Fingerprinting & Fix Verification" width="100%" />
</p>

---

## Audit Assessment Sequence Flow

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / User
    participant Web as Mola UI (Next.js)
    participant API as /api/scan (Route Handler)
    participant Guard as SSRF & URL Validator
    participant Scanner as HTTP & Audit Engines
    participant Target as Target Website
    participant AI as AI Assistant / issues.md

    Dev->>Web: Enter Website URL & Select Scan Mode
    Web->>API: POST /api/scan { url, mode }
    API->>Guard: Validate Scheme, DNS & Reject Private Subnets (SSRF)
    alt Unsafe or Loopback Target
        Guard-->>API: Reject 400 Bad Request
        API-->>Web: Display Guardrail Error
    else Safe Public Target
        Guard-->>API: Normalized URL Approved
        API->>Scanner: Initiate Controlled HTTP Request
        Scanner->>Target: GET with Timeout & Max Payload Limits
        Target-->>Scanner: Headers, Status, TLS & HTML Body
        Scanner->>Scanner: Execute Security, Performance, SEO, a11y & Tech Engines
        Scanner->>Scanner: Group Duplicates, Normalize & Sort by Priority
        Scanner-->>API: Structured ScanResult
        API-->>Web: 200 OK (Telemetry, Findings & Pass Checks)
        Web->>Dev: Render Interactive Telemetry Report
        Dev->>Web: Export issues.md / Copy Markdown
        Dev->>AI: Feed issues.md to Gemini / Claude / Cursor
        Dev->>Target: Deploy Code & Infrastructure Fixes
        Dev->>Web: Click "Rescan" for Fix Verification
        Web->>Dev: Highlight Resolved vs Remaining Findings
    end
```

---

## Use Cases

- **Pre-Deployment Production Checklist** — Audit staging or production URLs to catch missing security headers, uncompressed payloads, and missing tags before public launches
- **Security Posture & Header Auditing** — Validate Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), frame-ancestors, and cookie flags across client websites
- **SEO & Search Indexing Diagnostics** — Check canonical URLs, meta descriptions, title tag lengths, and heading hierarchy structures
- **Accessibility & UX Compliance** — Pinpoint unlabelled form controls, missing image `alt` attributes, and absent root language declarations
- **Competitive & Technology Intelligence** — Discover frameworks, CDN edge providers, server types, and reverse proxy architectures powering competitor domains
- **AI-Assisted Automated Remediation** — Export standardized `issues.md` reports and feed them directly into AI coding agents to automate code changes
- **Fix Verification & Regression Testing** — Re-audit after deploying fixes to confirm resolved items and guarantee that no new defects were introduced
- **Client & Stakeholder Reporting** — Generate clean, verifiable evidence summaries without vanity badges to substantiate engineering recommendations

---

## 🚀 Quick Start

**Prerequisites:**
- **Node.js**: `v18.17.0` or higher (tested on Node v20 & v24)
- **npm**, **pnpm**, or **yarn**

### Installation & First Run

```bash
# 1. Clone the repository
git clone https://github.com/mizan989/Mola-Web_Auditor.git
cd Mola-Web_Auditor

# 2. Install dependencies
npm install

# 3. Start the development server
npm run dev
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser to begin auditing.

> [!NOTE]
> Mola operates 100% statelessly without external database requirements. Out of the box, all scanning, SSRF protection, telemetry parsing, and export generation run locally in volatile memory.

---

## Ways to Run Mola

- **Live Cloud Production** — Hosted live on Antideploy with continuous container deployment. [Try Live App](https://mola.antideploy.app)
- **Local Development** — Runs with hot-reloading using Next.js 16 and Turbopack. [Quick Start](#-quick-start)
- **Production Container Build** — Compile optimized server bundle (`npm run build`) and serve via Node.js runtime (`npm start`).

---

## ☁️ Auditor Workspaces & Views

Mola delivers dedicated interfaces tailored for the web auditing lifecycle:

- **Instant Audit Hub (`/`)** — Clean, distraction-free search input with suggested URL presets, scan mode toggle (Quick vs. Deep), and real-time stage progress tracker
- **Findings Telemetry & Priority Engine** — Categorized cards with severity filters (`High`, `Medium`, `Low`, `Fix First`), raw evidence inspect drawers, and one-click copyable remediation code
- **Technology & Infrastructure Inspector** — Live breakdown of server headers, TTFB response benchmarks, HTTP protocol versions, SSL/TLS status, and framework detection
- **Fix Verification & Rescan Comparator** — Automatic diffing banner comparing successive scan runs to highlight `🟢 Resolved`, `🟡 Remaining`, and `🔴 New Issues`
- **AI-Ready Export Studio** — One-click markdown (`issues.md`) generation formatted specifically for prompt-based coding assistants, alongside raw JSON downloads

---

## 🤖 Use Mola with Coding Agents

Mola is specifically designed to bridge the gap between audit discovery and resolution via modern AI coding assistants (Gemini, Claude, Cursor, GitHub Copilot).

### 1. Exporting `issues.md`

Click **Export issues.md** on any completed audit to generate a self-contained markdown file structured for LLM ingestion:

```markdown
# Audit Issues & Recommendations — example.com

> **Audit Metadata**
> - Target: `https://example.com`
> - Total Findings: 15 (High: 4, Medium: 5, Low: 6)

## Prioritized Action Items

### 1. [HIGH] Content-Security-Policy (CSP) Header Missing
- **Category**: `security`
- **Priority**: `CRITICAL`
- **Affected Target**: `HTTP Response Headers`
- **Why It Matters**: A robust CSP acts as a defense-in-depth shield against XSS...

**Concrete Evidence:**
```text
response.headers["content-security-policy"] → undefined
```

**Recommended Fix:**
Define a strict Content-Security-Policy header restricting script execution.
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
```
```

### 2. Prompting Your Coding Agent

Provide `issues.md` directly to **Google Gemini**, **Claude**, **Cursor**, or **GitHub Copilot**:

> *"Here is the `issues.md` report from Mola Web Auditor. Fix the critical security headers in our reverse proxy configuration and add missing image dimensions in our React templates."*

### 3. Executing Audits via API

Coding agents can also invoke the API endpoint directly to programmatically audit target URLs:

```bash
curl -X POST https://mola.antideploy.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "mode": "quick"}'
```

The endpoint returns structured JSON conforming to the audit schema, including `findings`, `passedChecks`, `httpInfo`, `technologies`, and `performanceMetrics`.

---

## ✨ Features

### Evidence-First Observation Engine

Every finding produced by Mola is grounded in direct, reproducible observations:
- **Raw Headers**: Exact header keys and missing directives surfaced verbatim.
- **Affected Elements**: CSS selectors, tag names, and element code snippets extracted directly from HTML.
- **Measurable Metrics**: Microsecond-accurate TTFB timings and byte compression ratios.

### Zero Vanity Scores

Traditional audit suites rely on synthetic scores that reward superficial optimizations while ignoring fundamental vulnerabilities. Mola provides:
- **Ranked Engineering Priorities**: Actionable severity tiers (`High`, `Medium`, `Low`, `Fix First`).
- **Impact-Based Ordering**: Issues that expose sites to security breaches or search indexing failure are highlighted first.
- **Passed Checks Audit**: Clear visibility into what is already configured correctly.

### SSRF-Hardened Security Architecture

Auditing arbitrary URLs poses severe Server-Side Request Forgery risks. Mola implements hardened defense-in-depth controls:
- **Protocol Whitelisting**: Only `http:` and `https:` schemes are permitted. Schemes such as `file:`, `ftp:`, `data:`, and `javascript:` are immediately rejected.
- **Private IP Blocking**: Proactively resolves and blocks RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Loopback & Cloud Metadata Isolation**: Drops requests targeting `127.0.0.1`, `localhost`, `::1`, and cloud provider metadata interfaces (`169.254.169.254`, `metadata.google.internal`).
- **Timeout & Quota Defenses**: Strict 12-second abort timeouts and 5MB payload caps prevent memory exhaustion attacks.

---

## Core Audit Engines & Rules Matrix

Mola runs checks across five primary disciplines plus technology and network infrastructure discovery:

| Category | Checks & Rules | Detection Method | Severity |
|---|---|---|---|
| **Security** | Content-Security-Policy (CSP) | Analyzes `Content-Security-Policy` header presence and flags `'unsafe-inline'` / `'unsafe-eval'` | **HIGH** |
| **Security** | Strict-Transport-Security (HSTS) | Verifies `Strict-Transport-Security` header with minimum 1-year max-age on HTTPS | **HIGH** |
| **Security** | Clickjacking Defenses | Checks for `X-Frame-Options` or CSP `frame-ancestors` directives | **MEDIUM** |
| **Security** | MIME-Type Sniffing Protection | Verifies `X-Content-Type-Options: nosniff` | **MEDIUM** |
| **Security** | Insecure Mixed Content | Detects unencrypted `http://` scripts, stylesheets, and images on HTTPS hosts | **HIGH** |
| **Security** | Version Banner Leakage | Flags exact daemon versions in `Server` or `X-Powered-By` headers | **LOW** |
| **Performance** | TTFB Latency Benchmark | Measures Time-To-First-Byte against strict latency tiers (<300ms, 300–800ms, >800ms) | **HIGH / MED** |
| **Performance** | HTTP Payload Compression | Checks for modern Brotli (`br`), Gzip (`gzip`), or Zstandard (`zstd`) compression | **MEDIUM** |
| **Performance** | Render-Blocking Scripts | Detects synchronous `<script>` tags in `<head>` without `defer` or `async` | **MEDIUM** |
| **Performance** | Explicit Image Dimensions | Flags images missing `width` and `height` attributes to prevent Cumulative Layout Shift (CLS) | **LOW** |
| **SEO** | Document `<title>` Hygiene | Verifies `<title>` existence, minimum length (>15 chars), and maximum desktop limit (<70 chars) | **HIGH / LOW** |
| **SEO** | Meta Description | Evaluates `<meta name="description">` presence and optimal character length (50–160 chars) | **MEDIUM** |
| **SEO** | Canonical Link Declaration | Checks for `<link rel="canonical">` to prevent duplicate indexing penalties | **MEDIUM** |
| **SEO** | Heading Hierarchy (H1) | Enforces single primary `<h1>` presence and validates logical heading nesting | **MEDIUM / LOW** |
| **SEO** | OpenGraph & Social Metadata | Validates `og:title` and `og:image` tags for link preview generation | **LOW** |
| **Accessibility** | Image `alt` Text Audit | Identifies images lacking descriptive `alt` attributes, providing element snippets | **HIGH** |
| **Accessibility** | Root Language Definition | Verifies valid BCP 47 `lang` attribute on the root `<html>` element | **HIGH** |
| **Accessibility** | Form Control Labeling | Detects input fields lacking associated `<label>`, `aria-label`, or accessible names | **MEDIUM** |
| **Accessibility** | Semantic Landmarks | Confirms presence of `<main>`, `<header>`, and landmark containers | **LOW** |
| **Best Practices** | Modern HTML5 DOCTYPE | Detects legacy quirks-mode triggers by verifying `<!DOCTYPE html>` | **MEDIUM** |
| **Best Practices** | UTF-8 Character Encoding | Confirms explicit `<meta charset="utf-8">` declaration | **LOW** |
| **Best Practices** | Obsolete Markup Scrutiny | Identifies deprecated tags (`<center>`, `<font>`, `<marquee>`, `<blink>`) | **LOW** |

---

## ⚙️ Configuration & Environment

Mola runs out of the box with zero required environment variables. Optional configurations can be specified in `.env.local`:

```env
PORT=3000
HOSTNAME=0.0.0.0
```

---

## 📂 Architecture & Code Structure

```text
d:/PROJECTS/Mola/
├── .antideploy.json             # Antideploy configuration (mola.antideploy.app)
├── app/
│   ├── api/
│   │   └── scan/
│   │       └── route.ts          # Secure scan API route handler
│   ├── privacy/
│   │   └── page.tsx              # Stateless privacy policy
│   ├── terms/
│   │   └── page.tsx              # Acceptable use terms
│   ├── globals.css               # Design tokens & Tailwind CSS v4 setup
│   ├── layout.tsx                # Root layout, metadata & brand navbar
│   └── page.tsx                  # Interactive Auditor application UI
├── assets/
│   ├── logo.png                  # High-resolution brand mark (512x512)
│   ├── screenshot1.png           # Hero & scanner UI preview
│   └── screenshot2.png           # Telemetry & verification UI preview
├── lib/
│   ├── compare.ts                # Client/server-isolated audit comparison engine
│   ├── exportJson.ts             # JSON export & file download helpers
│   └── exportMarkdown.ts         # issues.md Markdown generator
├── public/
│   ├── apple-touch-icon.png      # Apple touch icon (180x180)
│   ├── favicon-32x32.png         # 32x32 Favicon
│   ├── favicon.ico               # Multi-size Favicon (16/32/48)
│   ├── icon-192.png              # PWA icon (192x192)
│   ├── logo.png                  # Brand logo
│   ├── screenshot1.png           # Hero UI asset
│   └── screenshot2.png           # Telemetry UI asset
├── server/
│   ├── orchestrator.ts           # Scan pipeline & verification comparator
│   ├── scanners/
│   │   ├── a11y.ts               # Accessibility (alt, lang, landmarks)
│   │   ├── bestPractices.ts      # Doctype, UTF-8, deprecated markup
│   │   ├── http.ts               # HTTP telemetry, headers, TLS, latency
│   │   ├── performance.ts        # TTFB, compression, caching, scripts
│   │   ├── security.ts           # CSP, HSTS, X-Frame, cookies, mixed content
│   │   ├── seo.ts                # Title, meta description, canonical, h1-h6
│   │   └── tech.ts               # Technology detection engine (Wappalyzer)
│   └── validators/
│       └── url.ts                # SSRF guardrails & IP allowlist validation
├── types/
│   └── audit.ts                  # Finding, Result & Verification schemas
├── next.config.ts                # Next.js security headers configuration
├── package.json                  # Dependencies & scripts
├── postcss.config.mjs            # Tailwind CSS PostCSS plugin
├── tsconfig.json                 # Strict TypeScript configuration
└── README.md                     # Project overview & documentation
```

---

## ☁️ Cloud Deployment

Mola is deployed and hosted on **Antideploy** with continuous integration on every push:

- **Production URL**: [https://mola.antideploy.app](https://mola.antideploy.app)
- **Deployment Spec**: [`.antideploy.json`](.antideploy.json) links to the project and triggers builds on each commit to `main`.
- **Containerized Runtime**: Optimized Next.js 16 container, fully SSRF-hardened and stateless.

---

## Verification & Quality Bar

```bash
# Typecheck TypeScript codebase
npm run typecheck

# Build optimized production bundle
npm run build

# Start production server
npm run start
```

---

## Contributing

We welcome contributions from the developer and security community!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-audit-rule`)
3. Commit your changes (`git commit -m 'feat: add cache-control audit rule'`)
4. Push to the branch (`git push origin feature/new-audit-rule`)
5. Open a [Pull Request](https://github.com/mizan989/Mola-Web_Auditor/pulls)

---

## Support the Project

**Enjoying Mola?** Give us a ⭐ on [GitHub](https://github.com/mizan989/Mola-Web_Auditor) to help others discover evidence-based web auditing!

---

## Acknowledgements

Mola is built with gratitude towards the open-source engineering ecosystem:

- [Next.js](https://nextjs.org/) & [React 19](https://react.dev/) — Modern React framework and server architecture
- [Tailwind CSS v4](https://tailwindcss.com/) — Modern utility-first styling engine
- [Lucide Icons](https://lucide.dev/) — Consistent, high-precision developer iconography
- [Antideploy](https://antideploy.com/) — Fast, zero-friction containerized cloud deployment

---

## 👤 Author

**Md Mizan**

- **GitHub**: [@mizan989](https://github.com/mizan989)
- **LinkedIn**: [in/mizan989](https://www.linkedin.com/in/mizan989)
- **Instagram**: [@mizan989](https://instagram.com/mizan989)
- **X (Twitter)**: [@mizan989](https://x.com/mizan989)
- **Repository**: [Mola-Web_Auditor](https://github.com/mizan989/Mola-Web_Auditor)
- **Live Site**: [mola.antideploy.app](https://mola.antideploy.app)

---

<div align="center">

> [!NOTE]
> **Audit Integrity & Non-Destructive Scanning:** Mola inspects observable public HTTP responses, TLS handshakes, and DOM structures. It strictly blocks loopback and private subnets, does not perform aggressive fuzzing, and respects remote server integrity.

</div>
