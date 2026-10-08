# Mola — UI Design System & Component Guidelines

This document specifies the design philosophy, color system, typographic hierarchy, and accessibility standards for Mola Web Auditor.

---

## 1. Design Philosophy: Quiet Developer Aesthetic

Mola embraces a **"Quiet Developer Aesthetic"**—an editorial, calm, and information-dense interface that prioritizes signal over noise.

- **Zero Gamification**: No artificial 0–100 progress rings, animated confetti, or vanity score meters.
- **Evidence-First Hierarchy**: Data presentation prioritizes raw facts: status, title, description, concrete evidence, impact, and remediation.
- **Restrained Visual Language**: Subtle borders, soft translucent glassmorphism (`backdrop-blur-md`), and high-contrast typography designed for long reading sessions.
- **Speed & Predictability**: Immediate visual feedback, authentic indeterminate progress states, and zero fabricated countdown timers.

---

## 2. Color System & Design Tokens

Mola uses CSS custom properties defined in [`app/globals.css`](app/globals.css):

### Neutral Palette
| Token | Value | Purpose |
|---|---|---|
| `--background` | `#CCD0CF` | Main application background (soft neutral canvas) |
| `--surface` | `#E8ECEB` | Secondary elevated surface |
| `--border` | `rgba(74, 92, 106, 0.25)` | Subtle structural divider |
| `--text-primary` | `#06141B` | Primary reading typography (deep near-black) |
| `--muted` | `#4A5C6A` | Secondary descriptions, timestamps, and subtitles |
| `--deep` | `#11212D` | Primary interactive buttons, dark code blocks |
| `--dark` | `#06141B` | High-contrast emphasis and headers |
| `--white` | `#FFFFFF` | Contrasting text within dark badges and code blocks |

### Semantic Severity Tokens
| Severity Tier | Accent Color | Background Tint | Border Tint |
|---|---|---|---|
| **High / Critical** | `#DC2626` (`--error`) | `#FEF2F2` (`--error-bg`) | `rgba(220, 38, 38, 0.3)` |
| **Medium** | `#D97706` (`--warning`) | `#FFFBEB` (`--warning-bg`) | `rgba(217, 119, 6, 0.3)` |
| **Low / Info** | `#2563EB` (Blue) | `#EFF6FF` | `rgba(37, 99, 235, 0.3)` |
| **Passing** | `#059669` (`--success`) | `#ECFDF5` (`--success-bg`) | `rgba(5, 150, 105, 0.3)` |

---

## 3. Typographic Hierarchy

Typography relies on modern system UI font stacks with monospace accents for technical telemetry:

- **Page Headlines**: 4xl to 7xl (`font-extrabold`, tracking tight, leading tight).
- **Section Headers**: 2xl to 4xl (`font-extrabold`, tracking tight).
- **Finding Card Titles**: Base to lg (`font-bold`, color `var(--dark)`).
- **Body & Explanations**: Sm to base (`text-[var(--muted)]`, leading relaxed).
- **Telemetry & Technical Data**: Monospace font (`font-mono`, text-xs / text-[11px]) for URLs, HTTP status codes, headers, and timings.
- **Badges & Micro-Labels**: Text-[10px] / text-[11px] (`font-extrabold`, uppercase, tracking-wider).

---

## 4. Information Architecture: Finding Card Order

To maximize developer scanning efficiency, finding cards conform to an ordered reading hierarchy:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. SEVERITY / CONFIDENCE / STATUS / CATEGORY BADGES                         │
│ 2. FINDING TITLE (Concise Technical Label)                                  │
│ 3. SHORT EXPLANATION (One to two sentence summary)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. CONCRETE EVIDENCE (Dark Monospace Block: Raw headers / element snippets) │
│    • Expected Condition                                                     │
│    • Affected Resource                                                      │
│    • Limitation (if applicable)                                             │
│ 5. WHY IT MATTERS (Security / Performance / SEO real-world impact)          │
│ 6. RECOMMENDED FIX (Actionable instructions & copyable code snippet)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Accessibility & Interactive Standards

1. **Multi-Channel Severity Communication**: Severity is never communicated via color alone. Every badge pairs a visible text label (`HIGH`, `MEDIUM`, `LOW`), an explicit icon (`ShieldAlert`, `AlertTriangle`, `Info`), and an accessible `aria-label`.
2. **Keyboard Navigation & Focus Management**:
   - All interactive cards, accordion triggers, and buttons feature visible focus indicators: `focus-visible:ring-2 focus-visible:ring-[var(--deep)]`.
   - Card expansion supports both `Enter` and `Space` keyboard triggers.
3. **No Nested Interactive Elements**: Buttons never contain nested buttons or anchors. Card container headers use accessible `<div role="button" tabIndex={0}>` to prevent DOM validation errors.
4. **Contrast Compliance**: All text combinations meet or exceed WCAG AA 4.5:1 contrast ratios.
5. **Non-Disruptive Notifications**: Export actions and clipboard copies utilize inline polite toasts (`role="status"`, `aria-live="polite"`) rather than blocking browser `alert()` dialogs.
6. **Responsive Layouts**: Designed mobile-first, ensuring all grids, cards, tables, and monospace code blocks collapse gracefully on viewports from 360px up to 4K displays.
