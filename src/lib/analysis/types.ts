export enum Verdict {
  AUTHENTIC = "AUTHENTIC",
  MODIFIED_FORMAT_ONLY = "MODIFIED_FORMAT_ONLY",
  TAMPERED = "TAMPERED",
  NOT_FOUND = "NOT_FOUND",
  ANALYSIS_UNAVAILABLE = "ANALYSIS_UNAVAILABLE",
}

export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export type CheckStatus = "PASSED" | "FAILED" | "NOT_CHECKED";

export interface CheckResult {
  name: string;
  status: CheckStatus;
  detail?: string;
}

export interface AnalysisChange {
  location?: string;
  description: string;
  kind?: string;
}

/** Normalized 0–1 box relative to page render, or pixel coords if absolute. */
export interface BoundingBox {
  x: number;
  y: number;
  width: number;
  height: number;
  /** Optional label, e.g. "image removed". */
  label?: string;
  /** When true, coordinates are 0–1 fractions of page size. */
  normalized?: boolean;
}

export interface VisualPageDiff {
  page: number;
  changedPercent: number;
  boxes: BoundingBox[];
  /** Small PNG thumbnails (base64, no data: prefix) for UI overlays. */
  uploadedThumbnailBase64?: string;
  originalThumbnailBase64?: string;
  thumbnailWidth?: number;
  thumbnailHeight?: number;
}

export interface AnalysisResult {
  verdict: Verdict;
  confidence: Confidence;
  checks: CheckResult[];
  changes: AnalysisChange[];
  notChecked: string[];
  /**
   * Metadata/encoding/structure differences that never decide TAMPERED.
   * Shown under "File was also re-saved by a different program".
   */
  formatDifferences?: AnalysisChange[];
  /** Per-page visual diff details when the visual check ran. */
  visualPages?: VisualPageDiff[];
}

export interface Analyzer {
  supports(mime: string, ext: string): boolean;
  analyze(original: Buffer, uploaded: Buffer): Promise<AnalysisResult>;
}

/** Content checks that can produce TAMPERED. */
export const CONTENT_CHECK_NAMES = [
  "text",
  "visual",
  "embedded-images",
  "annotations",
  "form-fields",
  "structure-content",
] as const;

/** Format/metadata checks — FAILED here → MODIFIED_FORMAT_ONLY only. */
export const FORMAT_CHECK_NAMES = [
  "structure",
  "file-properties",
  "metadata",
] as const;
