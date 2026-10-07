export type FindingCategory =
  | "security"
  | "performance"
  | "seo"
  | "accessibility"
  | "best-practices";

export type FindingSeverity = "high" | "medium" | "low";

export type FindingPriority = "critical" | "fix-first" | "recommended" | "investigate";

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  priority: FindingPriority;
  title: string;
  description: string;
  whyItMatters: string;
  evidence: string;
  affectedTarget?: string;
  recommendation: string;
  codeSnippet?: string;
  instancesCount?: number;
  instances?: string[];
}

export interface PassedCheck {
  id: string;
  category: FindingCategory;
  title: string;
  detail: string;
}

export interface DetectedTechnology {
  name: string;
  category: "Framework" | "CMS" | "CDN / Host" | "Analytics" | "Server" | "Library" | "UI / Fonts";
  version?: string;
  confidence: number;
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
  errorMessage?: string;
  summary: {
    totalFindings: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    passedCount: number;
    categoryCounts: Record<FindingCategory, number>;
  };
  findings: Finding[];
  passedChecks: PassedCheck[];
  technologies: DetectedTechnology[];
  httpInfo: HttpInspectionInfo;
  performanceMetrics: PerformanceMetrics;
  seoData: SeoInspection;
  accessibilitySummary: AccessibilityInspection;
}

export interface VerificationComparison {
  previousScanTimestamp: string;
  newScanTimestamp: string;
  targetUrl: string;
  resolvedFindings: Finding[];
  remainingFindings: Finding[];
  newFindings: Finding[];
  totalPrevious: number;
  totalCurrent: number;
}
