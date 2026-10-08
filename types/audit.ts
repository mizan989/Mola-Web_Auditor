export type FindingCategory =
  | "security"
  | "performance"
  | "seo"
  | "accessibility"
  | "best-practices";

export type FindingSeverity = "high" | "medium" | "low";

export type FindingPriority = "critical" | "fix-first" | "recommended" | "investigate";

export type FindingConfidence = "high" | "medium" | "low";

export type FindingState =
  | "confirmed"
  | "not_detected"
  | "unable_to_check"
  | "failed"
  | "observation"
  | "recommendation";

export interface StructuredEvidence {
  id?: string;
  sourceUrl?: string;
  affectedTarget?: string;
  observation: string;
  expectedCondition?: string;
  evidenceType?: string;
  metadata?: Record<string, unknown>;
  limitations?: string;

  // Phase 6 First-Class Evidence Engine Dimensions
  whatWasObserved?: string;
  where?: string;
  howObserved?: string;
  whyItMatters?: string;
  whatToDo?: string;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  priority: FindingPriority;
  state: FindingState;
  confidence: FindingConfidence;
  title: string;
  description: string;
  whyItMatters: string;
  evidence: string;
  structuredEvidence?: StructuredEvidence;
  affectedTarget?: string;
  recommendation: string;
  codeSnippet?: string;
  instancesCount?: number;
  instances?: string[];
  limitations?: string;
  correlationKey?: string;
}

export interface PassedCheck {
  id: string;
  category: FindingCategory;
  title: string;
  detail: string;
  state?: FindingState;
  confidence?: FindingConfidence;
  structuredEvidence?: StructuredEvidence;
}

export interface DetectedTechnology {
  name: string;
  category: "Framework" | "CMS" | "CDN / Host" | "Analytics" | "Server" | "Library" | "UI / Fonts";
  version?: string;
  confidence: number;
  evidence?: string;
}

export interface HttpInspectionInfo {
  statusCode: number;
  statusText: string;
  protocol: string;
  responseTimeMs: number;
  contentLength: number;
  contentType: string;
  isHttps: boolean;
  redirectChain: string[];
  headers: Record<string, string>;
  isTruncated?: boolean;
}

export interface PerformanceMetrics {
  ttfbMs: number;
  totalPayloadKb: number;
  compression: string | null;
  cacheControl: string | null;
  scriptsCount: number;
  stylesheetsCount: number;
  imagesCount: number;
}

export interface SeoInspection {
  title: string | null;
  titleLength: number;
  metaDescription: string | null;
  descriptionLength: number;
  canonicalUrl: string | null;
  robots: string | null;
  ogTitle: string | null;
  ogImage: string | null;
  h1Count: number;
  headings: { level: number; text: string }[];
}

export interface AccessibilityInspection {
  imagesTotal: number;
  imagesMissingAlt: number;
  missingAltElements: string[];
  hasLang: boolean;
  lang: string | null;
  hasMainLandmark: boolean;
  hasHeaderLandmark: boolean;
  inputsMissingLabel: number;
}

export interface ScanResult {
  scanId: string;
  targetUrl: string;
  finalUrl: string;
  hostname: string;
  scanTimestamp: string;
  scanDurationMs: number;
  scanMode: "quick" | "deep";
  status: "completed" | "partial" | "failed";
  completeness: "full" | "partial";
  errorMessage?: string;
  summary: {
    totalFindings: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    passedCount: number;
    categoryCounts: Record<FindingCategory, number>;
    stateCounts?: Record<FindingState, number>;
    confidenceCounts?: Record<FindingConfidence, number>;
  };
  findings: Finding[];
  passedChecks: PassedCheck[];
  technologies: DetectedTechnology[];
  httpInfo: HttpInspectionInfo;
  performanceMetrics: PerformanceMetrics;
  seoData: SeoInspection;
  accessibilitySummary: AccessibilityInspection;
  reconnaissance?: ReconnaissanceMap;
  limitations?: string[];
  browserExecution?: BrowserExecutionResult;
  coverage?: AuditCoverageSummary;
}

export interface CategoryCoverage {
  category: FindingCategory;
  attempted: number;
  completed: number;
  unableToCheck: number;
  failed: number;
  limitations: string[];
}

export interface AuditCoverageSummary {
  scanMode: "quick" | "deep";
  attemptedChecks: number;
  completedChecks: number;
  unableToCheckCount: number;
  failedChecksCount: number;
  limitations: string[];
  categoryBreakdown: Record<FindingCategory, CategoryCoverage>;
  unverifiedChecks?: string[];
}

export type VerificationStatus =
  | "fixed"
  | "still_present"
  | "changed"
  | "new"
  | "unable_to_verify";

export interface VerificationFindingDiff {
  findingId: string;
  category: FindingCategory;
  title: string;
  status: VerificationStatus;
  affectedTarget: string;
  previousFinding?: Finding;
  currentFinding?: Finding;
  changes?: {
    severity?: { from: FindingSeverity; to: FindingSeverity };
    priority?: { from: FindingPriority; to: FindingPriority };
    state?: { from?: FindingState; to?: FindingState };
    confidence?: { from?: FindingConfidence; to?: FindingConfidence };
    affectedTarget?: { from: string; to: string };
    evidence?: { from?: string; to?: string };
    recommendation?: { from?: string; to?: string };
    instancesCount?: { from?: number; to?: number };
    materialDetails?: string;
  };
  reason?: string;
}

export interface VerificationComparison {
  previousScanTimestamp: string;
  newScanTimestamp: string;
  targetUrl: string;
  resolvedFindings: Finding[];
  remainingFindings: Finding[];
  changedFindings: Finding[];
  newFindings: Finding[];
  unableToVerifyFindings?: Finding[];
  diffs?: VerificationFindingDiff[];
  totalPrevious: number;
  totalCurrent: number;
  summary?: {
    fixed: number;
    stillPresent: number;
    changed: number;
    new: number;
    unableToVerify: number;
  };
}

export interface BoundedHttpResponse {
  statusCode: number;
  statusText: string;
  protocol: string;
  isHttps: boolean;
  responseTimeMs: number;
  contentLength: number;
  contentType: string;
}

export interface DiscoveredResources {
  scripts: string[];
  stylesheets: string[];
  images: string[];
  iframes: string[];
}

export interface AuditContextMetadata {
  scanId: string;
  userAgent: string;
  timestamp: string;
  isPartial?: boolean;
  failureReason?: string;
  validatedAddresses?: string[];
}

export interface AuditContext {
  targetUrl: string;
  finalUrl: string;
  hostname: string;
  scanMode: "quick" | "deep";
  redirectChain: string[];
  response: BoundedHttpResponse;
  headers: Record<string, string>;
  body: {
    text: string;
    byteLength: number;
    isTruncated: boolean;
  };
  timing: {
    startTime: number;
    ttfbMs: number;
    durationMs?: number;
  };
  discoveredResources: DiscoveredResources;
  technologyObservations: DetectedTechnology[];
  limitations: string[];
  metadata: AuditContextMetadata;
  recon?: ReconnaissanceMap;
}

export interface ReconTargetInfo {
  inputUrl: string;
  normalizedUrl: string;
  finalUrl: string;
  hostname: string;
  scheme: "http" | "https";
  port: number;
  ipAddresses?: string[];
}

export interface ReconRedirectHop {
  hopNumber: number;
  url: string;
}

export interface ReconBodyMetadata {
  byteLength: number;
  characterLength: number;
  isTruncated: boolean;
  maxBodyLimitBytes: number;
  contentType: string;
  charset?: string;
  hasHtmlDoctype: boolean;
}

export interface ReconSecurityObservation {
  type: string;
  observation: string;
  provenance: "header" | "transport" | "html" | "redirect";
  severity?: "info" | "warning";
}

export interface ReconnaissanceMap {
  target: ReconTargetInfo;
  redirectChain: ReconRedirectHop[];
  status: {
    code: number;
    text: string;
    protocol: string;
    ttfbMs: number;
  };
  headers: Record<string, string>;
  bodyMetadata: ReconBodyMetadata;
  discoveredResources: DiscoveredResources;
  technologySignals: DetectedTechnology[];
  securityObservations: ReconSecurityObservation[];
  limitations: string[];
  collectedAt: string;
}

export interface BrowserResourceObservation {
  url: string;
  resourceType: string;
  isMixedContent: boolean;
  isHttps: boolean;
}

export interface BrowserExecutionResult {
  isSupported: boolean;
  executed: boolean;
  limitationReason?: string;
  navigationDurationMs?: number;
  renderedDomByteLength?: number;
  observedResources?: BrowserResourceObservation[];
  jsRenderedContentDetected?: boolean;
  jsRenderedElementsCount?: number;
  renderedA11yIssuesCount?: number;
  runtimeMixedContentCount?: number;
  findings?: Finding[];
  passedChecks?: PassedCheck[];
}
