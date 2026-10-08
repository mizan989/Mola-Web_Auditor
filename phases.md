# Mola — Phased Upgrade Plan

## Purpose
This document defines the implementation order for upgrading Mola's audit engine using a stronger evidence-first security-auditing methodology while preserving Mola's existing product identity, workflow, and UI.

Implementation is phase-gated: complete one phase, test it, report the results, and stop. Do not begin the next phase until explicitly approved.

## Phase 0 — Restore and Protect the Existing Audit Workflow
**Goal:** Restore the currently broken audit flow before adding architectural improvements.

**Changes**
- Trace `URL input → scan mode → Audit button → client handler → /api/scan → validation → orchestrator → scanners → response → report`.
- Identify the exact regression introduced by recent changes.
- Fix only the regression.
- Verify Quick Scan, Deep Scan, and Audit actions.
- Verify `/api/scan` request/response compatibility.
- Check middleware, CSP, state handling, validation, error handling, and disabled-button conditions.
- Do not weaken SSRF/security controls.

**Exit criteria**
- Public URLs can be audited.
- Quick Scan, Deep Scan, and Audit work.
- Errors are visible.
- Existing security controls remain intact.
- Typecheck, lint, tests, and production build pass.

## Phase 1 — Explicit Evidence-First Audit Model
**Goal:** Make every audit check produce a truthful structured result.

Add explicit states:
`confirmed`, `not_detected`, `unable_to_check`, `failed`, `observation`, `recommendation`.

Add independent confidence:
`high`, `medium`, `low`.

Keep severity separate from confidence.

Define structured evidence containing, where applicable:
- source URL
- target/resource
- observed value
- expected condition
- evidence type
- relevant metadata
- limitations

**Exit:** Existing scanners can express the model; unavailable checks cannot appear as passes; severity and confidence are independent; tests cover all states.

## Phase 2 — Shared Audit Context
**Goal:** Give scanners one authoritative set of collected data.

Create an `AuditContext` containing only validated/collected data such as:
- normalized target URL
- validated redirect chain
- HTTP responses
- headers
- bounded body
- timing
- discovered resources
- technology observations
- scan mode
- limitations
- safe scan metadata

Define field ownership/lifecycle. Reduce duplicate fetching.

**Exit:** Scanners consume shared context where appropriate; unvalidated destinations cannot enter as trusted data; tests cover incomplete context.

## Phase 3 — Reconnaissance Layer
**Goal:** Map the target before specialized checks.

Collect deterministically:
- target normalization
- redirect chain
- status
- headers
- content type
- bounded body metadata
- discovered resources where safely available
- technology signals
- security-relevant observations

Recon is evidence collection, not a finding engine.

**Exit:** Structured surface map with provenance, explicit limits/failures, no SSRF bypass.

## Phase 4 — Replace Regex-Heavy HTML Analysis
**Goal:** Make HTML-derived checks structurally accurate.

Use a proper HTML parser for:
- title
- meta description
- canonical
- headings
- links
- forms
- labels
- scripts
- stylesheets
- images
- iframes
- media/resources

Replace fragile regex DOM interpretation. Preserve response-size limits and malformed-document handling.

**Exit:** SEO, labels, and resource extraction use parsed structure; tests cover malformed and deceptive HTML.

## Phase 5 — Separate Detection from Validation
Every meaningful rule has:
1. detection — find a candidate;
2. validation — gather enough evidence to confirm/reject.

Apply to:
- security headers
- cookies
- mixed content
- technology detection
- SRI
- iframe security
- accessibility
- SEO

Rejected candidates must not become confirmed findings.

**Exit:** Candidate validation outcomes are explicit; false-positive tests exist.

## Phase 6 — First-Class Evidence Engine
Create reusable evidence structures/helpers.

Every finding should answer:
- What was observed?
- Where?
- How?
- Why does it matter?
- What limitation exists?
- What should the developer do?

Update Markdown/JSON exports so evidence is preserved.

**Exit:** Findings are traceable and exported evidence matches internal evidence.

## Phase 7 — Independent Severity and Confidence
Severity = impact if true.
Confidence = certainty that the condition is true.

Do not use arbitrary numeric confidence scores or a global score.

Use explicit evidence-quality rules. Add confidence minimally to existing report UI only if useful.

**Exit:** Confirmed findings have severity and confidence; uncertain observations are clearly marked.

## Phase 8 — Specialized Audit Modules
Organize checks into:
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

Use shared context/evidence model. Remove duplicate logic only after behavior is preserved.

**Exit:** Clear module ownership and focused tests.

## Phase 9 — Finding Deduplication and Correlation
Create deterministic semantic correlation keys based on:
- category
- rule/check ID
- affected target/resource
- relevant condition

Merge true duplicates while preserving supporting evidence. Do not merge merely because titles resemble each other.

**Exit:** Duplicate noise is reduced; unrelated findings remain separate; tests cover true/false merges.

## Phase 10 — Strengthen Deep Scan with an Isolated Browser
Only implement if the actual deployment/runtime can safely run a browser.

If supported, add:
- isolated browser execution
- strict navigation timeout
- resource limits
- controlled network access
- validated redirects
- rendered DOM capture
- browser resource observation
- rendered accessibility checks
- JavaScript-rendered content
- actual resource/mixed-content observation

Browser execution must not bypass SSRF controls.

**Exit:** Deep Scan scope is documented, browser failures become explicit limitations, Quick Scan remains lightweight.

## Phase 11 — Improve Verification
Compare:
- finding state
- severity
- confidence
- evidence
- affected resource
- material details
- material recommendation changes

Classify:
- fixed
- still present
- changed
- new
- unable to verify

A finding must not be called fixed merely because it disappeared if the relevant check could not run.

**Exit:** Conservative evidence-aware verification with tests for every state.

## Phase 12 — Audit Coverage and Limitations
Track:
- attempted checks
- completed checks
- unable-to-check checks
- failed checks
- limitations
- scan mode

Show a compact report section if needed. Do not invent a percentage without rigorous methodology.

**Exit:** Users can distinguish “not found” from “not checked.”

## Phase 13 — Harden Security Architecture
Prioritize:
- DNS rebinding defense at connection time
- validated redirect destinations
- connection binding or equivalent safe request architecture
- network-level egress isolation
- trusted proxy handling for rate limiting
- global/distributed limits where deployment requires them
- complete scan resource limits
- safe error sanitization
- response-size limits
- timeout enforcement

If network isolation cannot be guaranteed, reduce scanner capability instead of weakening security.

**Exit:** SSRF defenses cover validation and actual connection behavior; redirects cannot escape validation; security claims match deployment; adversarial tests exist.

## Phase 14 — Documentation, CSP, Accessibility, Release Hardening
- Correct README/security/privacy claims.
- Integrate `PRD.md`, `RULES.md`, `ARCHITECTURE.md`, `SECURITY.md`, `DESIGN.md`, and `issues.md`.
- Fix `.gitignore` so governance Markdown files can be tracked.
- Resolve CSP conflict; use one authoritative CSP.
- Remove `unsafe-inline` where nonce-based CSP is intended.
- Fix nested interactive elements and keyboard/accessibility issues.
- Verify responsive/mobile behavior.
- Run complete validation.

**Exit:** Documentation is truthful; CSP is authoritative; accessibility is corrected; production build succeeds; no known release blocker remains.

## Phase-Gating Rule
After every phase:
1. Inspect changes.
2. Run relevant tests.
3. Run typecheck.
4. Run lint.
5. Run production build when practical.
6. Manually test affected functionality.
7. Review the diff for accidental changes.
8. Report files changed, exact changes, tests/results, limitations, and anything not implemented.
9. STOP.
10. Ask whether to continue to the next phase.

Never automatically continue.
