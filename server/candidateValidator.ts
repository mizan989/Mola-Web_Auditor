/**
 * Candidate Detection vs Evidence Validation Layer (Phase 5).
 * Enforces the two-stage auditing discipline:
 * 1. Detection — identify a candidate finding signal.
 * 2. Validation — evaluate supporting telemetry and context to confirm, reject, or mark as observation/unable_to_check.
 *
 * Rule: Rejected candidates MUST NEVER become confirmed findings.
 */

export type ValidationOutcome = "confirmed" | "rejected" | "insufficient_evidence";

export interface CandidateEvaluation<T = unknown> {
  ruleId: string;
  candidateTarget: string;
  outcome: ValidationOutcome;
  reason: string;
  candidateValue?: T;
  evidence?: unknown;
}

// ==========================================
// 1. Security Headers Candidates
// ==========================================

export interface HstsCandidateInput {
  isHttps: boolean;
  hstsHeader?: string;
}

export function validateHstsCandidate(input: HstsCandidateInput): CandidateEvaluation<string> {
  // If connection is plain HTTP, HSTS is not applicable (RFC 6797 §7.2)
  if (!input.isHttps) {
    return {
      ruleId: "sec-hsts-missing",
      candidateTarget: "Transport Layer",
      outcome: "rejected",
      reason: "HSTS header is strictly invalid over plain HTTP; candidate defect rejected for non-HTTPS target.",
    };
  }

  if (!input.hstsHeader) {
    return {
      ruleId: "sec-hsts-missing",
      candidateTarget: "Transport Layer",
      outcome: "confirmed",
      reason: "HTTPS response completely lacks Strict-Transport-Security header.",
    };
  }

  const maxAgeMatch = input.hstsHeader.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;

  if (maxAge === 0) {
    return {
      ruleId: "sec-hsts-disabled",
      candidateTarget: "Transport Layer",
      outcome: "confirmed",
      reason: "Strict-Transport-Security declares max-age=0, actively disabling HSTS.",
      candidateValue: input.hstsHeader,
    };
  }

  return {
    ruleId: "sec-hsts-missing",
    candidateTarget: "Transport Layer",
    outcome: "rejected",
    reason: `Valid HSTS header declared with max-age=${maxAge}.`,
    candidateValue: input.hstsHeader,
  };
}

export interface CspUnsafeCandidateInput {
  cspHeader?: string;
}

export function validateCspUnsafeCandidate(input: CspUnsafeCandidateInput): CandidateEvaluation<string> {
  if (!input.cspHeader) {
    return {
      ruleId: "sec-csp-unsafe",
      candidateTarget: "response.headers['content-security-policy']",
      outcome: "rejected",
      reason: "No CSP header present; candidate handled by sec-csp-missing rule.",
    };
  }

  const csp = input.cspHeader;
  const scriptSrcMatch = csp.match(/(?:^|;)\s*script-src\s+([^;]+)/i);
  const defaultSrcMatch = csp.match(/(?:^|;)\s*default-src\s+([^;]+)/i);
  const scriptDirective = scriptSrcMatch ? scriptSrcMatch[1] : defaultSrcMatch ? defaultSrcMatch[1] : "";

  const hasUnsafeInline = /'unsafe-inline'/i.test(scriptDirective);
  const hasNonce = /'nonce-[a-zA-Z0-9+/=_-]+'/i.test(scriptDirective);
  const hasStrictDynamic = /'strict-dynamic'/i.test(scriptDirective);
  const hasHash = /'sha(?:256|384|512)-/i.test(scriptDirective);
  const hasUnsafeEval = /'unsafe-eval'/i.test(scriptDirective);

  if (hasUnsafeEval) {
    return {
      ruleId: "sec-csp-unsafe",
      candidateTarget: "response.headers['content-security-policy']",
      outcome: "confirmed",
      reason: "Script execution permits 'unsafe-eval', allowing dynamic code evaluation.",
      candidateValue: scriptDirective,
    };
  }

  // CSP Level 3: Nonce, hash, or strict-dynamic strictly overrides and neutralizes 'unsafe-inline' in modern browsers
  if (hasUnsafeInline && (hasNonce || hasStrictDynamic || hasHash)) {
    return {
      ruleId: "sec-csp-unsafe",
      candidateTarget: "response.headers['content-security-policy']",
      outcome: "rejected",
      reason: "CSP Level 3 defense: 'unsafe-inline' is neutralized by nonce, hash, or strict-dynamic. Candidate rejected.",
      candidateValue: scriptDirective,
    };
  }

  if (hasUnsafeInline) {
    return {
      ruleId: "sec-csp-unsafe",
      candidateTarget: "response.headers['content-security-policy']",
      outcome: "confirmed",
      reason: "Script execution permits 'unsafe-inline' without nonce, hash, or strict-dynamic defense.",
      candidateValue: scriptDirective,
    };
  }

  return {
    ruleId: "sec-csp-unsafe",
    candidateTarget: "response.headers['content-security-policy']",
    outcome: "rejected",
    reason: "No unsafe script directives detected in CSP.",
    candidateValue: scriptDirective,
  };
}

export interface XfoCandidateInput {
  xfoHeader?: string;
  cspHeader?: string;
}

export function validateXfoCandidate(input: XfoCandidateInput): CandidateEvaluation<string> {
  // W3C CSP Level 2/3: frame-ancestors supersedes X-Frame-Options
  if (input.cspHeader && /frame-ancestors\s+/i.test(input.cspHeader)) {
    return {
      ruleId: "sec-xfo-missing",
      candidateTarget: "response.headers['x-frame-options']",
      outcome: "rejected",
      reason: "W3C CSP frame-ancestors directive is present and supersedes X-Frame-Options. Candidate rejected.",
    };
  }

  if (!input.xfoHeader) {
    return {
      ruleId: "sec-xfo-missing",
      candidateTarget: "response.headers['x-frame-options']",
      outcome: "confirmed",
      reason: "Neither X-Frame-Options nor CSP frame-ancestors are present.",
    };
  }

  return {
    ruleId: "sec-xfo-missing",
    candidateTarget: "response.headers['x-frame-options']",
    outcome: "rejected",
    reason: `X-Frame-Options is declared: ${input.xfoHeader}.`,
    candidateValue: input.xfoHeader,
  };
}

// ==========================================
// 2. Cookie Candidates
// ==========================================

export interface CookieCandidateInput {
  cookieString: string;
  isHttps: boolean;
}

export function validateCookieCandidate(input: CookieCandidateInput): CandidateEvaluation<{
  issues: string[];
  cookie: string;
}> {
  const { cookieString, isHttps } = input;
  const isSecure = /\bsecure\b/i.test(cookieString);
  const isHttpOnly = /\bhttponly\b/i.test(cookieString);
  const hasSameSite = /\bsamesite=(?:lax|strict|none)\b/i.test(cookieString);

  const issues: string[] = [];

  // Secure flag only makes sense on HTTPS
  if (!isSecure && isHttps) {
    issues.push("missing 'Secure' flag");
  }
  if (!isHttpOnly) {
    issues.push("missing 'HttpOnly' flag");
  }
  if (!hasSameSite) {
    issues.push("missing 'SameSite' attribute");
  }

  if (issues.length > 0) {
    return {
      ruleId: "sec-cookie-insecure",
      candidateTarget: "Set-Cookie Header",
      outcome: "confirmed",
      reason: `Cookie missing essential hardening flags: ${issues.join(", ")}.`,
      candidateValue: { issues, cookie: cookieString },
    };
  }

  return {
    ruleId: "sec-cookie-insecure",
    candidateTarget: "Set-Cookie Header",
    outcome: "rejected",
    reason: "Cookie specifies Secure, HttpOnly, and SameSite attributes.",
    candidateValue: { issues: [], cookie: cookieString },
  };
}

// ==========================================
// 3. Mixed Content Candidates
// ==========================================

export interface MixedContentCandidateInput {
  url: string;
  isHttps: boolean;
  tag?: string;
}

export function validateMixedContentCandidate(input: MixedContentCandidateInput): CandidateEvaluation<string> {
  const { url, isHttps, tag } = input;

  if (!isHttps) {
    return {
      ruleId: "sec-mixed-content",
      candidateTarget: url,
      outcome: "rejected",
      reason: "Target is plain HTTP; mixed content rules apply strictly to HTTPS sites.",
      candidateValue: url,
    };
  }

  if (!url || !url.toLowerCase().startsWith("http://")) {
    return {
      ruleId: "sec-mixed-content",
      candidateTarget: url,
      outcome: "rejected",
      reason: "URL is not requested over plain HTTP scheme.",
      candidateValue: url,
    };
  }

  // Exempt standard XML namespaces or documentation schemas that are not fetched
  const lowerUrl = url.toLowerCase();
  if (
    lowerUrl.startsWith("http://www.w3.org/") ||
    lowerUrl.startsWith("http://schema.org/") ||
    lowerUrl.startsWith("http://xmlns.com/")
  ) {
    return {
      ruleId: "sec-mixed-content",
      candidateTarget: url,
      outcome: "rejected",
      reason: "URL is a non-fetched XML namespace / metadata schema URI. Candidate rejected.",
      candidateValue: url,
    };
  }

  return {
    ruleId: "sec-mixed-content",
    candidateTarget: tag ? `<${tag} src="${url}">` : url,
    outcome: "confirmed",
    reason: `Insecure subresource requested over unencrypted HTTP: ${url}`,
    candidateValue: url,
  };
}

// ==========================================
// 4. Technology Detection Candidates
// ==========================================

export interface TechCandidateInput {
  techName: string;
  rawSignal: string;
  hasDirectProof: boolean;
  hasClusterProof: boolean;
  evidence: string;
}

export function validateTechnologyCandidate(input: TechCandidateInput): CandidateEvaluation<string> {
  const { techName, hasDirectProof, hasClusterProof, evidence } = input;

  // React candidate validation:
  if (techName === "React") {
    if (!hasDirectProof) {
      return {
        ruleId: "tech-react",
        candidateTarget: "React Framework",
        outcome: "rejected",
        reason: "Generic substring match (e.g. 'reaction') lacks DOM/bundle proof. Candidate rejected.",
      };
    }
    return {
      ruleId: "tech-react",
      candidateTarget: "React Framework",
      outcome: "confirmed",
      reason: evidence,
      candidateValue: techName,
    };
  }

  // Tailwind CSS candidate validation:
  if (techName === "Tailwind CSS") {
    if (!hasDirectProof && !hasClusterProof) {
      return {
        ruleId: "tech-tailwind",
        candidateTarget: "Tailwind CSS",
        outcome: "rejected",
        reason: "Isolated utility class (e.g. 'flex') lacks stylesheet/CDN or cluster proof. Candidate rejected.",
      };
    }
    return {
      ruleId: "tech-tailwind",
      candidateTarget: "Tailwind CSS",
      outcome: "confirmed",
      reason: evidence,
      candidateValue: techName,
    };
  }

  // Generic direct proof validation for others (Next.js, Vue, Angular, WordPress, etc.)
  if (hasDirectProof) {
    return {
      ruleId: `tech-${techName.toLowerCase()}`,
      candidateTarget: techName,
      outcome: "confirmed",
      reason: evidence,
      candidateValue: techName,
    };
  }

  return {
    ruleId: `tech-${techName.toLowerCase()}`,
    candidateTarget: techName,
    outcome: "rejected",
    reason: "Signal lacks conclusive proof. Candidate rejected.",
  };
}

// ==========================================
// 5. Subresource Integrity (SRI) Candidates
// ==========================================

export interface SriCandidateInput {
  src: string;
  host: string;
  finalUrl: string;
  hasIntegrity: boolean;
}

export function validateSriCandidate(input: SriCandidateInput): CandidateEvaluation<string> {
  const { src, host, finalUrl, hasIntegrity } = input;

  // Relative or protocol-relative/absolute host check
  if (!src.startsWith("//") && !src.startsWith("http://") && !src.startsWith("https://")) {
    return {
      ruleId: "sec-sri-missing",
      candidateTarget: src,
      outcome: "rejected",
      reason: "First-party relative script path; SRI is not required for first-party origin assets.",
      candidateValue: src,
    };
  }

  let scriptHost: string;
  try {
    scriptHost = new URL(src, finalUrl).hostname;
  } catch {
    return {
      ruleId: "sec-sri-missing",
      candidateTarget: src,
      outcome: "insufficient_evidence",
      reason: "Could not parse script URL for hostname comparison.",
      candidateValue: src,
    };
  }

  // If hosted on the same origin/hostname as the target page:
  if (scriptHost === host) {
    return {
      ruleId: "sec-sri-missing",
      candidateTarget: src,
      outcome: "rejected",
      reason: "First-party script hosted on target origin; SRI is only evaluated for external third-party CDNs.",
      candidateValue: src,
    };
  }

  // External script:
  if (hasIntegrity) {
    return {
      ruleId: "sec-sri-missing",
      candidateTarget: src,
      outcome: "rejected",
      reason: "External script declares valid cryptographic integrity attribute.",
      candidateValue: src,
    };
  }

  return {
    ruleId: "sec-sri-missing",
    candidateTarget: src,
    outcome: "confirmed",
    reason: `External third-party script from ${scriptHost} lacks subresource integrity (SRI) hash.`,
    candidateValue: src,
  };
}

// ==========================================
// 6. Iframe Security Candidates
// ==========================================

export interface IframeSecurityCandidateInput {
  src: string;
  hasSandbox: boolean;
  isLazy: boolean;
}

export function validateIframeSecurityCandidate(
  input: IframeSecurityCandidateInput
): {
  sandboxEvaluation: CandidateEvaluation<string>;
  lazyEvaluation: CandidateEvaluation<string>;
} {
  const { src, hasSandbox, isLazy } = input;

  const sandboxEvaluation: CandidateEvaluation<string> = hasSandbox
    ? {
        ruleId: "sec-iframe-sandbox-missing",
        candidateTarget: src,
        outcome: "rejected",
        reason: "Iframe declares sandbox attribute.",
        candidateValue: src,
      }
    : {
        ruleId: "sec-iframe-sandbox-missing",
        candidateTarget: src,
        outcome: "confirmed",
        reason: `Embedded iframe ${src} lacks restrictive sandbox attribute.`,
        candidateValue: src,
      };

  const lazyEvaluation: CandidateEvaluation<string> = isLazy
    ? {
        ruleId: "perf-iframe-lazy-missing",
        candidateTarget: src,
        outcome: "rejected",
        reason: "Iframe declares loading='lazy'.",
        candidateValue: src,
      }
    : {
        ruleId: "perf-iframe-lazy-missing",
        candidateTarget: src,
        outcome: "confirmed",
        reason: `Embedded iframe ${src} missing loading='lazy'.`,
        candidateValue: src,
      };

  return { sandboxEvaluation, lazyEvaluation };
}

// ==========================================
// 7. Accessibility Form Input Candidates
// ==========================================

export interface InputLabelCandidateInput {
  type: string;
  id?: string;
  hasAria: boolean;
  hasTitle: boolean;
  hasLabelFor: boolean;
  isWrappedInLabel: boolean;
}

export function validateInputLabelCandidate(input: InputLabelCandidateInput): CandidateEvaluation<string> {
  const { type, hasAria, hasTitle, hasLabelFor, isWrappedInLabel } = input;

  // Exempt non-interactive / self-labelling inputs
  if (["hidden", "submit", "button", "reset", "image"].includes(type.toLowerCase())) {
    return {
      ruleId: "a11y-inputs-unlabelled",
      candidateTarget: `<input type="${type}">`,
      outcome: "rejected",
      reason: `Input type '${type}' is non-text or self-labelling under WCAG guidelines.`,
    };
  }

  // Accessible name sources
  if (hasAria) {
    return {
      ruleId: "a11y-inputs-unlabelled",
      candidateTarget: input.id || "input",
      outcome: "rejected",
      reason: "Accessible name provided via aria-label or aria-labelledby.",
    };
  }

  if (hasTitle) {
    return {
      ruleId: "a11y-inputs-unlabelled",
      candidateTarget: input.id || "input",
      outcome: "rejected",
      reason: "Accessible name provided via title attribute.",
    };
  }

  if (isWrappedInLabel) {
    return {
      ruleId: "a11y-inputs-unlabelled",
      candidateTarget: input.id || "input",
      outcome: "rejected",
      reason: "Input is wrapped inside a parent <label> element.",
    };
  }

  if (hasLabelFor) {
    return {
      ruleId: "a11y-inputs-unlabelled",
      candidateTarget: input.id || "input",
      outcome: "rejected",
      reason: "Input is explicitly associated with an external <label for='...'> element.",
    };
  }

  return {
    ruleId: "a11y-inputs-unlabelled",
    candidateTarget: input.id || "input",
    outcome: "confirmed",
    reason: "Interactive form input has no accessible name (no label, wrapping label, aria-label, or title).",
  };
}

export interface ImageAltCandidateInput {
  hasAltAttribute: boolean;
  src?: string;
}

export function validateImageAltCandidate(input: ImageAltCandidateInput): CandidateEvaluation<string> {
  if (input.hasAltAttribute) {
    return {
      ruleId: "a11y-images-missing-alt",
      candidateTarget: input.src || "<img>",
      outcome: "rejected",
      reason: "Image declares an alt attribute (either descriptive or decorative alt=\"\"). Candidate rejected.",
      candidateValue: input.src,
    };
  }

  return {
    ruleId: "a11y-images-missing-alt",
    candidateTarget: input.src || "<img>",
    outcome: "confirmed",
    reason: "Image completely lacks an alt attribute under WCAG 1.1.1 Non-text Content.",
    candidateValue: input.src,
  };
}

// ==========================================
// 8. SEO Canonical Candidates
// ==========================================

export interface CanonicalCandidateInput {
  canonicals: string[];
}

export function validateCanonicalCandidate(input: CanonicalCandidateInput): {
  missingEvaluation: CandidateEvaluation<string>;
  multipleEvaluation?: CandidateEvaluation<string[]>;
} {
  const { canonicals } = input;

  if (canonicals.length === 0) {
    return {
      missingEvaluation: {
        ruleId: "seo-canonical-missing",
        candidateTarget: "<head> Links",
        outcome: "confirmed",
        reason: "Document contains zero canonical link tags.",
      },
    };
  }

  if (canonicals.length > 1) {
    return {
      missingEvaluation: {
        ruleId: "seo-canonical-missing",
        candidateTarget: "<head> Links",
        outcome: "rejected",
        reason: "Canonical links are present.",
      },
      multipleEvaluation: {
        ruleId: "seo-canonical-multiple",
        candidateTarget: "<head> Links",
        outcome: "confirmed",
        reason: `Found ${canonicals.length} conflicting canonical tags.`,
        candidateValue: canonicals,
      },
    };
  }

  return {
    missingEvaluation: {
      ruleId: "seo-canonical-missing",
      candidateTarget: "<head> Links",
      outcome: "rejected",
      reason: `Single valid canonical declared: ${canonicals[0]}.`,
      candidateValue: canonicals[0],
    },
  };
}
