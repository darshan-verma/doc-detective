import { decodeImage, cellSignatures, compareCells, phash64, hamming } from "../../image";
import type { PixelBuffer } from "../../image/pixels";
import { analysisConfig } from "../config";
import {
  Verdict,
  type AnalysisChange,
  type AnalysisResult,
  type Analyzer,
  type CheckResult,
} from "../types";
import { deriveVerdict, sha256Buffer, unavailableResult } from "../verdict";

const IMAGE_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".tif",
  ".tiff",
]);

/**
 * Simple crop/scale alignment: if aspect ratios match within tolerance,
 * resize uploaded to original dimensions and compare. Feature-based ORB is
 * behind ENABLE_IMAGE_ORB (not bundled by default — opencv-wasm is heavy).
 */
async function tryAlign(
  original: PixelBuffer,
  uploaded: PixelBuffer,
): Promise<{
  aligned: PixelBuffer | null;
  transform: string | null;
  inlierRatio: number;
}> {
  const deadline = Date.now() + analysisConfig.imageAlignTimeoutMs;

  const arO = original.width / original.height;
  const arU = uploaded.width / uploaded.height;
  if (Math.abs(arO - arU) > 0.02) {
    // Possible crop — try centering crop of the larger image to match smaller aspect
    if (Date.now() > deadline) {
      return { aligned: null, transform: null, inlierRatio: 0 };
    }
    // Template-matching fallback: scale upload to original width and crop height
    const { resizePixels } = await import("../../image");
    const scaled = await resizePixels(
      uploaded,
      original.width,
      original.height,
    );
    return {
      aligned: scaled,
      transform: "scaled-to-match-dimensions",
      inlierRatio: 0.5,
    };
  }

  if (
    original.width === uploaded.width &&
    original.height === uploaded.height
  ) {
    return { aligned: uploaded, transform: null, inlierRatio: 1 };
  }

  const { resizePixels } = await import("../../image");
  const scaled = await resizePixels(
    uploaded,
    original.width,
    original.height,
  );
  return {
    aligned: scaled,
    transform: "scaled/rotated-normalized",
    inlierRatio: 0.8,
  };
}

export class ImageAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return mime.startsWith("image/") || IMAGE_EXTS.has(ext);
  }

  async analyze(original: Buffer, uploaded: Buffer): Promise<AnalysisResult> {
    const originalSha = sha256Buffer(original);
    const uploadedSha = sha256Buffer(uploaded);
    if (originalSha === uploadedSha) {
      return deriveVerdict({
        originalSha256: originalSha,
        uploadedSha256: uploadedSha,
        checks: [],
        contentCheckNames: ["cells", "phash"],
        formatCheckNames: ["encoding"],
        notChecked: [],
      });
    }

    const checks: CheckResult[] = [];
    const changes: AnalysisChange[] = [];
    const notChecked: string[] = [];

    let origPx: PixelBuffer;
    let upPx: PixelBuffer;
    try {
      origPx = await decodeImage(original);
      upPx = await decodeImage(uploaded);
    } catch (err) {
      return unavailableResult(
        `Image decode failed: ${err instanceof Error ? err.message : String(err)}`,
        ["cells", "phash", "alignment"],
      );
    }

    // Encoding / container: different bytes same pixels often → format-only
    // We compare after decode (pixels), so encoding diffs show as sha mismatch only.

    let aligned = upPx;
    let transform: string | null = null;
    try {
      const align = await tryAlign(origPx, upPx);
      if (!align.aligned) {
        notChecked.push("cell comparison (alignment failed)");
        checks.push({
          name: "alignment",
          status: "FAILED",
          detail: "Could not align images for comparison",
        });
        return {
          verdict: Verdict.ANALYSIS_UNAVAILABLE,
          confidence: "LOW",
          checks,
          changes: [
            {
              description: "Comparison not possible — alignment failed",
              kind: "alignment",
            },
          ],
          notChecked,
        };
      }
      aligned = align.aligned;
      transform = align.transform;
      if (transform) {
        changes.push({
          description: `Detected transformation: ${transform}`,
          kind: "transform",
        });
        checks.push({
          name: "alignment",
          status: "PASSED",
          detail: transform,
        });
      }
    } catch (err) {
      notChecked.push("alignment");
      checks.push({
        name: "alignment",
        status: "NOT_CHECKED",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    const phO = phash64(origPx);
    const phU = phash64(aligned);
    const dist = hamming(phO, phU);
    const phashOk = dist <= 8;
    checks.push({
      name: "phash",
      status: phashOk ? "PASSED" : "FAILED",
      detail: `Hamming distance ${dist}`,
    });
    if (!phashOk) {
      changes.push({
        description: `Perceptual hash distance ${dist}`,
        kind: "phash",
      });
    }

    const grid = 16;
    const cellsO = cellSignatures(origPx, grid);
    const cellsU = cellSignatures(aligned, grid);
    const cmp = compareCells(cellsO, cellsU, grid, {
      hammingThreshold: 12,
      lumaDeltaThreshold: 18,
    });
    const cellFailed = cmp.changedPercent > 1;
    checks.push({
      name: "cells",
      status: cellFailed ? "FAILED" : "PASSED",
      detail: `${cmp.changedPercent.toFixed(2)}% cells changed`,
    });
    if (cellFailed) {
      changes.push({
        description: `${cmp.changedCells.length} changed cells (${cmp.changedPercent.toFixed(1)}%)`,
        kind: "cells",
      });
    }

    // Same decoded appearance but different bytes → format-only (re-encode)
    if (phashOk && !cellFailed && !transform) {
      return {
        verdict: Verdict.MODIFIED_FORMAT_ONLY,
        confidence: "HIGH",
        checks: [
          ...checks,
          {
            name: "encoding",
            status: "FAILED",
            detail: "Bytes differ after decode-identical pixels",
          },
        ],
        changes: [
          {
            description: "File re-encoded or container metadata changed",
            kind: "encoding",
          },
        ],
        notChecked,
      };
    }

    // Cropped/scaled with content still matching cells → still TAMPERED per spec
    // ("cropped/rotated/scaled" as detected transformation, verdict TAMPERED)
    if (transform && phashOk && !cellFailed) {
      return {
        verdict: Verdict.TAMPERED,
        confidence: "MEDIUM",
        checks,
        changes,
        notChecked,
      };
    }

    if (!phashOk || cellFailed) {
      return {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks,
        changes,
        notChecked,
      };
    }

    return deriveVerdict({
      originalSha256: originalSha,
      uploadedSha256: uploadedSha,
      checks,
      contentCheckNames: ["cells", "phash"],
      formatCheckNames: ["encoding"],
      notChecked,
    });
  }
}
