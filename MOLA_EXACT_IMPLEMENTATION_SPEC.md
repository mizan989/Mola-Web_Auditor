# Mola — Exact Implementation Specification

This file is the strict implementation specification for the phased upgrade. It defines what should be edited, added, replaced, or removed so an AI coding agent does not invent product decisions.

## Global Rules
- Inspect the repository before editing.
- Treat the current repository as the source of truth for existing behavior.
- Preserve working functionality.
- Do not redesign the UI.
- Do not replace the stack.
- Do not add accounts, dashboards, billing, AI chat, arbitrary scoring, CI/CD product mode, or a separate active security-scanner product.
- Do not copy another project's UI/product.
- Never fabricate findings, evidence, tests, security guarantees, browser behavior, or coverage.
- Never weaken security controls to make tests pass.
- Reuse existing components, types, helpers, and tests where safe.
- Avoid unnecessary dependencies.
- If something cannot be implemented safely, stop and report the limitation.

# PHASE 0 — Audit Workflow Regression
Inspect the complete flow:
`app/page.tsx → scan state/mode → Audit button → client handler → /api/scan → middleware/CSP → validation → orchestrator → scanners → response → report`.

Inspect recent git diff/status. Find the actual regression.

Check:
- button disabled state
- form submission
- handlers
- scan mode values
- request method/body
- API response parsing
- error handling
- AbortController
- middleware/CSP
- session state
- scanner exceptions
- route exports
- environment-specific code

Fix only the regression. Do not bypass validation.

Test a public target such as `https://example.com` in Quick and Deep modes, report rendering, errors, and rescan.

# PHASE 1 — Audit Result Model
Add explicit result states:
`confirmed | not_detected | unable_to_check | failed | observation | recommendation`.

Add confidence:
`high | medium | low`.

Keep severity independent.

Add structured evidence with, where applicable:
- evidence ID
- source URL
- affected target/resource
- observation
- expected condition
- evidence type
- relevant metadata
- limitation

Update central types, scanners, orchestrator, report serialization, Markdown export, JSON export, and tests.

Do not allow unavailable/failed checks to appear as successful negative results.

Test every state and severity/confidence combination.

# PHASE 2 — AuditContext
Add a shared server-side `AuditContext` containing only validated/collected information:
- normalized target
- validated redirect chain
- bounded HTTP response
- headers
- bounded body
- timing
- discovered resources
- technology observations
- scan mode
- limitations
- safe metadata

Construct it after URL validation. Never treat an unvalidated redirect as trusted.

Refactor scanners to consume shared context instead of duplicate requests where possible.

Test normal, failed, truncated, redirect, and partial contexts.

# PHASE 3 — Reconnaissance
Add deterministic recon collection for:
- normalized URL
- redirect chain
- status
- headers
- content type
- bounded body/size
- safely discovered resources
- technology signals
- security-relevant observations

Recon produces observations/evidence, not findings.

Preserve SSRF protections and explicit failure/limit states.

# PHASE 4 — HTML Parser
Add the smallest appropriate maintained HTML parser compatible with the current stack.

Replace regex-based DOM interpretation for:
- title/meta/canonical
- headings
- links
- forms/labels
- scripts/stylesheets
- images
- iframes
- media

Keep regex only where it is appropriate for narrow non-DOM tasks.

Preserve body-size limits and malformed HTML handling.

Add fixtures for malformed HTML, nested labels, duplicate IDs, multiple canonicals, relative/absolute resources, and misleading strings inside scripts/styles.

# PHASE 5 — Detection vs Validation
Refactor each meaningful rule into candidate detection followed by evidence validation.

Apply to:
- headers
- cookies
- mixed content
- tech detection
- SRI
- iframe security
- accessibility
- SEO

A rejected candidate must not become a confirmed finding. Represent insufficient evidence as observation/unable-to-check as appropriate.

Add false-positive tests.

# PHASE 6 — Evidence Engine
Create reusable evidence helpers.

Every finding must support:
- observation
- location
- method/provenance
- impact explanation
- limitation
- recommendation

Update Markdown/JSON/copy output so evidence is not lost.

Test evidence integrity and serialization round-trips.

# PHASE 7 — Severity + Confidence
Define severity as impact and confidence as certainty.

Add confidence to finding data.

Use explicit evidence-quality rules:
- direct evidence can be high;
- strong structural inference may be medium/high;
- heuristic evidence should not be presented as certainty;
- unsupported inference cannot become a confirmed finding.

Do not create a numeric confidence score or global Mola score.

Expose confidence minimally in the existing UI if needed.

# PHASE 8 — Specialized Modules
Organize existing/new logic into:
- HTTP/infrastructure
- security headers
- cookies
- TLS observations
- mixed content
- SEO
- accessibility
- best practices
- technology detection
- resource integrity
- iframe/resource safety

Use shared context/evidence model. Remove duplicate logic only after tests preserve behavior.

# PHASE 9 — Deduplication
Create deterministic semantic correlation keys using:
- category
- rule ID
- affected target/resource
- relevant condition

Merge only true duplicates. Preserve all meaningful supporting evidence.

Test:
- true duplicate
- same rule/different resource
- similar wording/different cause
- evidence preservation.

# PHASE 10 — Isolated Browser Deep Scan
First verify deployment/runtime support.

If supported, add isolated browser execution with:
- strict navigation timeout
- resource/process limits
- controlled network
- validated redirects
- cleanup
- rendered DOM
- resource observation
- rendered accessibility
- JS-rendered content
- appropriate browser timing

Browser networking must inherit SSRF protections and cannot bypass URL validation.

If safe isolation cannot be guaranteed, do not implement browser execution merely for feature parity. Document the limitation.

# PHASE 11 — Verification
Expand comparison to include:
- state
- severity
- confidence
- evidence
- affected resource
- material details
- material recommendation changes

Support:
`fixed | still_present | changed | new | unable_to_verify`.

Never call a finding fixed when the relevant check could not actually be performed.

Add tests for all states.

# PHASE 12 — Coverage
Add a compact coverage model tracking:
- attempted
- completed
- unable-to-check
- failed
- limitations
- scan mode

Add only a compact report section if needed.

Do not create a misleading percentage.

# PHASE 13 — Security Architecture
This is a release-critical phase.

Fix DNS rebinding at actual connection time. Resolving a hostname for validation and then separately calling `fetch(hostname)` is not sufficient by itself.

Use a verified safe architecture such as connection binding/safe resolver strategy and/or deployment network isolation, according to the actual runtime. Do not claim safety without verifying it.

Ensure:
- every redirect destination is validated;
- redirect count is bounded;
- network-level egress isolation is used where available;
- rate limiting uses a trustworthy client identity model;
- body/response/time/concurrency/scan limits remain enforced;
- backend errors are sanitized.

Add adversarial tests for localhost, private IPv4/IPv6, link-local, metadata, mapped IPv6, blocked redirects, DNS rebinding, oversized responses, timeouts, and redirect exhaustion.

If network isolation cannot be guaranteed, reduce arbitrary outbound scanning capability rather than weakening security.

# PHASE 14 — Release Hardening
Rewrite README/privacy/security claims to match verified implementation.

Track:
- `PRD.md`
- `RULES.md`
- `ARCHITECTURE.md`
- `SECURITY.md`
- `DESIGN.md`
- `issues.md`

Fix `.gitignore` so these documents are not accidentally ignored.

Resolve CSP inconsistency between middleware nonce CSP and static CSP. One policy must be authoritative. Do not retain `unsafe-inline` merely for convenience when nonce CSP is intended.

Fix nested interactive elements and verify keyboard/focus/screen-reader behavior.

Verify mobile/responsive behavior in a real browser.

Run typecheck, lint, tests, production build, Quick Scan, Deep Scan, rescan/verification, and exports. Report only commands/results actually obtained.
