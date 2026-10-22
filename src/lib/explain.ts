import {
  Verdict,
  type AnalysisChange,
  type AnalysisResult,
  type CheckResult,
  type Confidence,
} from "./analysis/types";

export interface PlainLanguageResult {
  headline: string;
  explanation: string;
  confidenceBadge: { label: "High" | "Medium" | "Low"; reason: string };
  whatWeChecked: Array<{
    name: string;
    status: string;
    detail?: string;
    /** Plain UI label */
    label: string;
  }>;
  whatWeCouldNotCheck: string[];
  formatDifferences: AnalysisChange[];
  /** Fixed disclaimer — never imply original contents are true. */
  disclaimer: string;
}

const DISCLAIMER =
  "This confirms the file is unchanged since it was certified, not that its original contents are true.";

const CONFIDENCE_LABEL: Record<Confidence, "High" | "Medium" | "Low"> = {
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

const CHECK_LABELS: Record<string, string> = {
  text: "Text",
  visual: "Appearance",
  "embedded-images": "Embedded images",
  annotations: "Annotations",
  "form-fields": "Form fields",
  "file-properties": "File properties",
  structure: "File properties",
  "structure-content": "Structure",
  sha256: "File hash",
  signature: "Signature",
  metadata: "File properties",
  bytes: "Bytes",
};

export function checkLabel(name: string): string {
  return CHECK_LABELS[name] ?? name.replace(/-/g, " ");
}

export function explainAnalysis(
  analysis: AnalysisResult,
  options?: { revoked?: boolean },
): PlainLanguageResult {
  const formatDifferences = analysis.formatDifferences ?? [];

  if (options?.revoked) {
    return {
      headline: "REVOKED",
      explanation:
        "This certificate has been revoked by its owner. Do not treat the file as currently certified, even if the bytes match.",
      confidenceBadge: {
        label: "High",
        reason: "Revocation is recorded in the transparency log",
      },
      whatWeChecked: mapChecks(analysis.checks),
      whatWeCouldNotCheck: analysis.notChecked,
      formatDifferences,
      disclaimer: DISCLAIMER,
    };
  }

  return {
    headline: headlineFor(analysis),
    explanation: explanationFor(analysis),
    confidenceBadge: {
      label: CONFIDENCE_LABEL[analysis.confidence],
      reason: confidenceReason(analysis),
    },
    whatWeChecked: mapChecks(analysis.checks),
    whatWeCouldNotCheck: [...analysis.notChecked],
    formatDifferences,
    disclaimer: DISCLAIMER,
  };
}

function mapChecks(checks: CheckResult[]) {
  return checks.map((c) => ({
    name: c.name,
    status: c.status,
    detail: c.detail,
    label: checkLabel(c.name),
  }));
}

function failedContentChecks(analysis: AnalysisResult): CheckResult[] {
  const content = new Set([
    "text",
    "visual",
    "embedded-images",
    "annotations",
    "form-fields",
    "structure-content",
  ]);
  return analysis.checks.filter(
    (c) => content.has(c.name) && c.status === "FAILED",
  );
}

function headlineFor(analysis: AnalysisResult): string {
  switch (analysis.verdict) {
    case Verdict.AUTHENTIC:
      return "Authentic";
    case Verdict.MODIFIED_FORMAT_ONLY:
      return "Modified (format only)";
    case Verdict.TAMPERED:
      return "Tampered";
    case Verdict.NOT_FOUND:
      return "Not found";
    case Verdict.ANALYSIS_UNAVAILABLE:
      return "Analysis unavailable";
    default:
      return "Unknown";
  }
}

function contentChangeSentence(analysis: AnalysisResult): string {
  const failed = failedContentChecks(analysis);
  const kinds = new Set(failed.map((c) => c.name));
  const parts: string[] = [];

  const textPages = analysis.changes
    .filter((c) => c.kind === "text")
    .map((c) => c.location)
    .filter(Boolean);
  if (kinds.has("text")) {
    if (textPages.length === 1) {
      parts.push(`Text changed on ${textPages[0]}`);
    } else if (textPages.length > 1) {
      parts.push(`Text changed on ${textPages.length} pages`);
    } else {
      parts.push("Text changed");
    }
  }
  if (kinds.has("visual")) {
    parts.push(
      parts.length ? "the page appearance changed" : "The page appearance changed",
    );
  }
  if (kinds.has("embedded-images")) {
    const img = analysis.changes.find((c) =>
      c.kind?.startsWith("embedded-image"),
    );
    parts.push(
      img?.description ??
        (parts.length ? "an embedded image changed" : "An embedded image changed"),
    );
  }
  if (kinds.has("annotations")) {
    parts.push(parts.length ? "annotations changed" : "Annotations changed");
  }
  if (kinds.has("form-fields")) {
    parts.push(parts.length ? "form fields changed" : "Form fields changed");
  }

  if (parts.length === 0) {
    const bits = analysis.changes
      .slice(0, 2)
      .map((c) => c.description)
      .join(" and ");
    return bits || "Content differs from the certified original.";
  }
  if (parts.length === 1) return `${parts[0]}.`;
  if (parts.length === 2) {
    const second = parts[1]!;
    const joined = second.charAt(0).toLowerCase() + second.slice(1);
    return `${parts[0]} and ${joined.replace(/\.$/, "")}.`;
  }
  const last = parts.pop()!;
  return `${parts.join(", ")}, and ${last.charAt(0).toLowerCase() + last.slice(1)}.`;
}

function explanationFor(analysis: AnalysisResult): string {
  switch (analysis.verdict) {
    case Verdict.AUTHENTIC:
      return "The uploaded file matches the certified original byte-for-byte. No content differences were detected.";
    case Verdict.MODIFIED_FORMAT_ONLY: {
      return "The text and appearance are identical, but the file was re-saved by another program or its container metadata changed.";
    }
    case Verdict.TAMPERED:
      return contentChangeSentence(analysis);
    case Verdict.ANALYSIS_UNAVAILABLE:
      return "We could not fully analyze this file. Some required checks did not run, so we cannot confirm authenticity.";
    case Verdict.NOT_FOUND:
      return "No matching certificate was found for this file.";
    default:
      return "Verification finished with an unexpected result.";
  }
}

function confidenceReason(analysis: AnalysisResult): string {
  if (analysis.notChecked.length > 0) {
    return `${analysis.notChecked.length} check(s) could not run`;
  }

  const failed = failedContentChecks(analysis);
  if (analysis.verdict === Verdict.TAMPERED && failed.length > 0) {
    const names = failed.map((c) => {
      if (c.name === "text") return "text";
      if (c.name === "visual") return "appearance";
      if (c.name === "embedded-images") return "embedded images";
      return checkLabel(c.name).toLowerCase();
    });
    const unique = [...new Set(names)];
    if (unique.length === 1) return `${unique[0]} differs`;
    if (unique.length === 2) return `${unique[0]} and ${unique[1]} both differ`;
    return `${unique.slice(0, -1).join(", ")} and ${unique[unique.length - 1]} differ`;
  }

  if (analysis.verdict === Verdict.MODIFIED_FORMAT_ONLY) {
    return "content matches; only file properties differ";
  }

  if (analysis.verdict === Verdict.AUTHENTIC) {
    return "exact byte match";
  }

  const passed = analysis.checks.filter((c) => c.status === "PASSED").length;
  return `${passed} check(s) passed`;
}

/** Banner color key for UI. */
export function bannerTone(
  verdict: Verdict | string,
  revoked?: boolean,
): "green" | "amber" | "red" | "grey" {
  if (revoked) return "red";
  switch (verdict) {
    case Verdict.AUTHENTIC:
    case "AUTHENTIC":
      return "green";
    case Verdict.MODIFIED_FORMAT_ONLY:
    case "MODIFIED_FORMAT_ONLY":
    case "MODIFIED_REENCODED":
      return "amber";
    case Verdict.TAMPERED:
    case "TAMPERED":
    case "REVOKED":
      return "red";
    default:
      return "grey";
  }
}
