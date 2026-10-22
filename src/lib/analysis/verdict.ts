import { createHash } from "crypto";
import {
  Verdict,
  type AnalysisResult,
  type CheckResult,
  type Confidence,
} from "./types";

export function sha256Buffer(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Derive verdict from checks + optional exact-hash shortcut.
 *
 * Rules:
 * - exact sha256 match → AUTHENTIC
 * - any FAILED content check → TAMPERED
 * - only metadata/encoding differences with all content checks PASSED →
 *   MODIFIED_FORMAT_ONLY
 * - a needed check could not run → never AUTHENTIC; ANALYSIS_UNAVAILABLE
 *   or lower confidence
 */
export function deriveVerdict(options: {
  originalSha256?: string;
  uploadedSha256?: string;
  checks: CheckResult[];
  /** Names of checks that are "content" (vs format/metadata). */
  contentCheckNames: string[];
  /** Names of checks that are format/metadata only. */
  formatCheckNames: string[];
  notChecked: string[];
  /** If true, a required content check was NOT_CHECKED. */
  requiredContentMissing?: boolean;
}): AnalysisResult {
  const {
    originalSha256,
    uploadedSha256,
    checks,
    contentCheckNames,
    formatCheckNames,
    notChecked,
    requiredContentMissing,
  } = options;

  if (
    originalSha256 &&
    uploadedSha256 &&
    originalSha256 === uploadedSha256
  ) {
    return {
      verdict: Verdict.AUTHENTIC,
      confidence: "HIGH",
      checks: [
        {
          name: "sha256",
          status: "PASSED",
          detail: "Exact content hash match",
        },
        ...checks,
      ],
      changes: [],
      notChecked,
    };
  }

  const contentChecks = checks.filter((c) =>
    contentCheckNames.includes(c.name),
  );
  const formatChecks = checks.filter((c) => formatCheckNames.includes(c.name));

  const anyContentFailed = contentChecks.some((c) => c.status === "FAILED");
  const allContentPassed =
    contentChecks.length > 0 &&
    contentChecks.every((c) => c.status === "PASSED");
  const anyFormatFailed = formatChecks.some((c) => c.status === "FAILED");

  if (requiredContentMissing || (contentChecks.length === 0 && notChecked.length > 0)) {
    return {
      verdict: Verdict.ANALYSIS_UNAVAILABLE,
      confidence: "LOW",
      checks,
      changes: [],
      notChecked,
    };
  }

  if (anyContentFailed) {
    return {
      verdict: Verdict.TAMPERED,
      confidence: confidenceFromChecks(checks),
      checks,
      changes: [],
      notChecked,
    };
  }

  if (allContentPassed && anyFormatFailed) {
    return {
      verdict: Verdict.MODIFIED_FORMAT_ONLY,
      confidence: "HIGH",
      checks,
      changes: [],
      notChecked,
    };
  }

  if (allContentPassed && !anyFormatFailed) {
    // Bytes differ but all checks passed — treat as format-only if we ran format checks
    if (formatChecks.length > 0) {
      return {
        verdict: Verdict.MODIFIED_FORMAT_ONLY,
        confidence: "MEDIUM",
        checks,
        changes: [],
        notChecked,
      };
    }
    return {
      verdict: Verdict.AUTHENTIC,
      confidence: "MEDIUM",
      checks,
      changes: [],
      notChecked,
    };
  }

  return {
    verdict: Verdict.ANALYSIS_UNAVAILABLE,
    confidence: "LOW",
    checks,
    changes: [],
    notChecked,
  };
}

function confidenceFromChecks(checks: CheckResult[]): Confidence {
  const failed = checks.filter((c) => c.status === "FAILED").length;
  const passed = checks.filter((c) => c.status === "PASSED").length;
  if (failed >= 2 || (failed >= 1 && passed >= 1)) return "HIGH";
  if (failed === 1) return "MEDIUM";
  return "LOW";
}

export function unavailableResult(
  reason: string,
  notChecked: string[],
): AnalysisResult {
  return {
    verdict: Verdict.ANALYSIS_UNAVAILABLE,
    confidence: "LOW",
    checks: [
      {
        name: "analyzer",
        status: "NOT_CHECKED",
        detail: reason,
      },
    ],
    changes: [],
    notChecked,
  };
}
