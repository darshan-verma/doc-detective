/**
 * All detection thresholds in one place.
 * Tune against tests/corpus; generated fakes will not match real editors.
 */

export const analysisConfig = {
  /** Max wall-clock ms for a single analyzer (worker timeout). */
  analyzerTimeoutMs: Number(process.env.ANALYZER_TIMEOUT_MS ?? 60_000),

  /** PDF visual render DPI (approx). */
  pdfRenderDpi: Number(process.env.PDF_RENDER_DPI ?? 100),

  /**
   * Pixelmatch threshold 0–1 for anti-aliasing tolerance between PDF renders.
   * Higher = more tolerant.
   */
  pdfPixelmatchThreshold: Number(process.env.PDF_PIXELMATCH_THRESHOLD ?? 0.1),

  /**
   * Max changed pixel percent on a page before visual check FAILS.
   * Below this with text match → still consider visual PASSED (AA noise).
   */
  pdfVisualChangedPercentMax: Number(
    process.env.PDF_VISUAL_CHANGED_PERCENT_MAX ?? 0.15,
  ),

  /** Min extractable chars on a page to treat text check as applicable. */
  pdfScannedTextMinChars: Number(process.env.PDF_SCANNED_TEXT_MIN_CHARS ?? 20),

  /** Enable tesseract OCR for scanned PDF diff display only. */
  enableOcr: process.env.ENABLE_OCR === "true",

  /** Image alignment wall-clock limit. */
  imageAlignTimeoutMs: Number(process.env.IMAGE_ALIGN_TIMEOUT_MS ?? 8_000),

  /** Min ORB/template inlier ratio to accept alignment warp. */
  imageAlignInlierRatioMin: Number(
    process.env.IMAGE_ALIGN_INLIER_RATIO_MIN ?? 0.35,
  ),

  /** AV: sample every N seconds for perceptual frame compare. */
  avSampleIntervalSec: Number(process.env.AV_SAMPLE_INTERVAL_SEC ?? 5),

  /** AV: max file size bytes before ANALYSIS_UNAVAILABLE. */
  avMaxBytes: Number(process.env.AV_MAX_BYTES ?? 100 * 1024 * 1024),

  /** AV: max duration seconds. */
  avMaxDurationSec: Number(process.env.AV_MAX_DURATION_SEC ?? 600),

  /** Eval script: max allowed false-positive rate (0–1). */
  evalFalsePositiveRateMax: Number(
    process.env.EVAL_FALSE_POSITIVE_RATE_MAX ?? 0.05,
  ),
} as const;
