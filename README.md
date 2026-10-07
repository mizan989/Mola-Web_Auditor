# Mola — Web Auditor

> A fast, open-source web auditing tool that analyzes websites, identifies actionable issues, and generates evidence-based reports for developers.

## Overview

**Mola** is a developer-focused web auditing tool built to answer a simple question:

> **What actually needs fixing on this website?**

Enter a URL, let Mola inspect the site, and receive a structured report containing actionable findings, supporting evidence, severity, impact, and recommendations.

Mola is designed to be useful before, during, and after development — without turning a website audit into an overloaded dashboard.

## Why Mola?

Mola focuses on:

- **Evidence over assumptions**
- **Actionable findings over vanity scores**
- **Clear explanations over technical noise**
- **Prioritization over endless issue lists**
- **Developer workflows over generic dashboards**

Mola does **not** invent findings, evidence, scores, or successful checks.

## Core Workflow

```text
Enter URL
    ↓
Scan
    ↓
Analyze
    ↓
Collect Evidence
    ↓
Prioritize Findings
    ↓
Generate Report
    ↓
Fix in Your Codebase
    ↓
Rescan & Verify
```

## Features

### Auditing

- Quick Scan
- Deep Scan
- Website technology detection
- HTTP and infrastructure inspection
- Visual snapshot
- Evidence-backed findings
- Severity classification
- Finding prioritization
- Duplicate finding grouping

### Reports

- Technical audit report
- Expandable findings
- Finding search and filters
- Scan summary
- Target URL details
- Evidence and affected resources
- Recommendations
- Partial/failed check states
- Markdown report generation
- `issues.md` export
- JSON export
- Copy Markdown
- Rescan and verification

### Developer Workflow

A generated `issues.md` file can be provided to an AI coding assistant such as ChatGPT, Claude, Cursor, or Antigravity.

The report instructs the coding assistant to inspect the actual codebase, verify findings, make only confirmed changes, and validate the result.

Mola does not attempt to replace your coding environment.

## What Mola Checks

Depending on scan mode and what can safely be observed, Mola can inspect areas such as:

- Page structure
- Metadata
- Links and resources
- HTTP behavior
- Security-related headers
- Performance-related signals
- Accessibility-related signals
- Technology information
- Resource loading
- Infrastructure-related observations
- Other evidence-based website issues

Not every check is available for every target.

Mola clearly distinguishes between:

- Confirmed findings
- Observations
- Passed checks
- Unavailable checks
- Failed checks
- Partial scan results

## No Arbitrary Score

Mola intentionally avoids a meaningless single-number website score.

Instead, it presents:

**What is wrong → Why it matters → Evidence → How to improve it → What to prioritize**

## Security

Security is a core part of Mola because the scanner accepts user-controlled URLs.

Mola treats submitted URLs and retrieved website content as untrusted.

Security considerations include:

- SSRF protection
- Private/internal network blocking
- Cloud metadata protection
- Redirect validation
- DNS rebinding defenses
- Network/egress isolation
- Request and resource limits
- Rate limiting
- Safe error handling
- Scanner isolation
- Dependency security
- Secret protection

See [`SECURITY.md`](SECURITY.md) for the complete security architecture and policy.

> Scanner safety is a release requirement. Security controls must never be disabled simply to make scanning easier.

## Design Philosophy

Mola follows a simple design principle:

> **Minimal, modern, premium, calm, fast, and intentional.**

The interface prioritizes:

- Clear information hierarchy
- Evidence-first reporting
- Responsive design
- Accessibility
- Fast interactions
- Restrained visual effects
- Consistent components
- Developer-focused UX

Mola intentionally avoids excessive glassmorphism, gradients, animations, cards, badges, decorative UI, and generic AI-dashboard patterns.

See [`DESIGN.md`](DESIGN.md) for the complete design system.

## Technology

The intended stack is centered around:

### Frontend

- Next.js
- TypeScript
- Tailwind CSS
- Lucide Icons

### Backend

- Node.js
- TypeScript
- Fastify or Express
- Playwright for browser-based/deep scanning where required

### Data

Mola is initially designed to be stateless and does not require a persistent database for its core workflow.

The final implementation must remain consistent with [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Documentation

| Document | Purpose |
|---|---|
| [`PRD.md`](PRD.md) | Product requirements and scope |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Technical architecture |
| [`RULES.md`](RULES.md) | Development and AI-agent rules |
| [`SECURITY.md`](SECURITY.md) | Security architecture and policy |
| [`DESIGN.md`](DESIGN.md) | UI/UX and design system |
| `README.md` | Project overview and getting started |

## Getting Started

### Prerequisites

- Node.js
- npm, pnpm, or another supported package manager
- Git

Additional requirements may be needed for browser-based scanning depending on the implementation.

### Clone

```bash
git clone https://github.com/mizan989/Mola-Web_Auditor.git
cd Mola-Web_Auditor
```

### Install

Install dependencies according to the repository's package structure.

```bash
npm install
```

### Environment Variables

If environment variables are required:

```bash
cp .env.example .env.local
```

Never commit secrets. The actual `.env.example` and application configuration are the source of truth.

### Development

```bash
npm run dev
```

The exact commands may differ between frontend and backend packages depending on the final repository structure.

## Production Verification

Before considering a change complete:

```text
Lint
 ↓
Type Check
 ↓
Tests
 ↓
Build
 ↓
Runtime Verification
 ↓
Security Verification
```

Security-sensitive changes require additional security testing.

## Contributing

Before making changes:

1. Read [`PRD.md`](PRD.md).
2. Read [`ARCHITECTURE.md`](ARCHITECTURE.md).
3. Read [`RULES.md`](RULES.md).
4. Read [`SECURITY.md`](SECURITY.md) for security-sensitive work.
5. Read [`DESIGN.md`](DESIGN.md) for UI work.

### Contribution Principles

- Keep changes focused.
- Reuse existing components and utilities.
- Do not introduce unnecessary dependencies.
- Do not weaken security controls.
- Do not fabricate audit findings or evidence.
- Preserve existing functionality.
- Test changes before submitting them.
- Update documentation when behavior changes.

## Responsible Security Disclosure

If you discover a security vulnerability in Mola, do not publicly disclose exploitable details before the issue has been investigated.

Provide:

- Clear description
- Reproduction steps
- Affected component
- Potential impact
- Relevant evidence

Avoid destructive testing, privacy violations, or unauthorized access to systems.

## Project Principles

```text
Evidence over assumptions.
Actionable findings over vanity scores.
Simple UX over visual noise.
Security over convenience.
Reuse over reinvention.
Transparency over false certainty.
```

## Status

Mola is under active development.

Features and architecture may evolve as implementation progresses. Documentation should be updated whenever the actual product or security posture changes.

## License

Mola is open source. See [`LICENSE`](LICENSE) for the applicable license.

---

**Built by Md Mizan**
