import { smartLineDiff } from "../diff/text";
import {
  Verdict,
  type AnalysisResult,
  type Analyzer,
} from "./types";
import { sha256Buffer } from "./verdict";

const TEXT_EXTS = new Set([
  ".txt",
  ".md",
  ".csv",
  ".json",
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".c",
  ".cpp",
  ".h",
  ".css",
  ".html",
  ".xml",
  ".yml",
  ".yaml",
  ".toml",
  ".ini",
  ".sh",
  ".env",
  ".log",
]);

export class TextAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return mime.startsWith("text/") || mime === "application/json" || TEXT_EXTS.has(ext);
  }

  async analyze(original: Buffer, uploaded: Buffer): Promise<AnalysisResult> {
    if (sha256Buffer(original) === sha256Buffer(uploaded)) {
      return {
        verdict: Verdict.AUTHENTIC,
        confidence: "HIGH",
        checks: [{ name: "sha256", status: "PASSED" }],
        changes: [],
        notChecked: [],
      };
    }

    const a = original.toString("utf8");
    const b = uploaded.toString("utf8");
    const diff = smartLineDiff(a, b);
    const substantive =
      (diff.counts?.added ?? 0) +
        (diff.counts?.removed ?? 0) +
        (diff.counts?.changed ?? 0) >
      0;

    if (substantive) {
      return {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks: [{ name: "text", status: "FAILED", detail: "Line content differs" }],
        changes: [{ description: "Text content differs", kind: "text" }],
        notChecked: [],
      };
    }

    // Only whitespace/formatting
    return {
      verdict: Verdict.MODIFIED_FORMAT_ONLY,
      confidence: "MEDIUM",
      checks: [
        { name: "text", status: "PASSED" },
        {
          name: "encoding",
          status: "FAILED",
          detail: "Bytes differ; normalized text matches",
        },
      ],
      changes: [{ description: "Encoding or line-ending differences only" }],
      notChecked: [],
    };
  }
}
