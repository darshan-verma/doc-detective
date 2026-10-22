import path from "path";
import { AvAnalyzer } from "./media/av";
import { ImageAnalyzer } from "./image/analyzer";
import { DocxAnalyzer } from "./office/docx";
import { PptxAnalyzer } from "./office/pptx";
import { XlsxAnalyzer } from "./office/xlsx";
import { PdfAnalyzer } from "./pdf/analyzer";
import { runAnalyzer } from "./runner";
import { TextAnalyzer } from "./text";
import type { AnalysisResult, Analyzer } from "./types";
import { Verdict } from "./types";
import { unavailableResult } from "./verdict";

export {
  Verdict,
  CONTENT_CHECK_NAMES,
  FORMAT_CHECK_NAMES,
  type AnalysisResult,
  type Analyzer,
  type CheckResult,
  type AnalysisChange,
  type Confidence,
  type CheckStatus,
  type VisualPageDiff,
  type BoundingBox,
} from "./types";
export { analysisConfig } from "./config";
export { deriveVerdict, sha256Buffer } from "./verdict";
export { runAnalyzer } from "./runner";
export { boundingBoxesFromDiffMask } from "./visual-boxes";

const analyzers: Analyzer[] = [
  new PdfAnalyzer(),
  new ImageAnalyzer(),
  new DocxAnalyzer(),
  new XlsxAnalyzer(),
  new PptxAnalyzer(),
  new AvAnalyzer(),
  new TextAnalyzer(),
];

export function selectAnalyzer(
  mimeType: string,
  originalName: string,
): Analyzer | null {
  const ext = path.extname(originalName).toLowerCase();
  return analyzers.find((a) => a.supports(mimeType, ext)) ?? null;
}

export async function analyzePair(options: {
  original: Buffer;
  uploaded: Buffer;
  mimeType: string;
  originalName: string;
}): Promise<AnalysisResult> {
  const analyzer = selectAnalyzer(options.mimeType, options.originalName);
  if (!analyzer) {
    // Binary fallback: exact hash already checked by caller; bytes differ
    return {
      verdict: Verdict.TAMPERED,
      confidence: "MEDIUM",
      checks: [
        {
          name: "bytes",
          status: "FAILED",
          detail: "No specialized analyzer; content hash differs",
        },
      ],
      changes: [{ description: "Binary content differs" }],
      notChecked: ["format-aware comparison"],
    };
  }

  try {
    return await runAnalyzer(analyzer, options.original, options.uploaded);
  } catch (err) {
    return unavailableResult(
      err instanceof Error ? err.message : String(err),
      ["full analysis"],
    );
  }
}
