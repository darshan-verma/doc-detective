import type { Certificate } from "@prisma/client";
import { z } from "zod";
import {
  findNewestVersion,
} from "../certificates/ownership";
import {
  checkRecordSignature,
  findClosestByPhash,
  getCertificateById,
  getCertificateBySha256,
  getCertificateByWatermarkToken,
  hashUploadedFile,
  publicCertificateView,
  readVerifiedStoredFile,
} from "../certificates/service";
import { explainAnalysis, type PlainLanguageResult } from "../explain";
import {
  analyzePair,
  Verdict,
  type AnalysisResult,
  type CheckResult,
} from "../analysis";
import { getConfig } from "../config";
import { diffFiles, type DiffResult } from "../diff";
import { AppError } from "../errors";
import { parseCertIdFromFilename } from "../filenames";
import { isLegacySignatureVersion } from "../signing";
import {
  applyLogIntegrityToVerifyResponse,
  checkCertificateRevocation,
  getLogChainStatus,
  revokeDisplayMessage,
  type LogIntegrity,
  type RevocationLogCheck,
} from "../trust";
import {
  aspectDiffers,
  cellSignatures,
  classifyImageChange,
  compareCells,
  decodeImage,
  detectBufferFormat,
  detectLocalizedPixelTamper,
  extract,
  extractImagePixelsFromPdf,
  formatDisplayName,
  isCertifiableImage,
  isPdfBuffer,
  isSharpDecodableImageFormat,
  PDF_IMAGE_UNAVAILABLE_MESSAGE,
  PDF_OVERLAY_TAMPER_REASON,
  phash64,
  resizePixels,
  type CellSignature,
  type ChangedCellCluster,
  type ImageChangeClass,
  type LocalizedRegion,
  type PixelBuffer,
} from "../image";
import { prisma } from "../prisma";

export const VerifyResultEnum = z.enum([
  "AUTHENTIC",
  "TAMPERED",
  "NOT_FOUND",
  "MODIFIED_REENCODED",
  "MODIFIED_FORMAT_ONLY",
  "ANALYSIS_UNAVAILABLE",
  "REVOKED",
]);
export type VerifyResultType = z.infer<typeof VerifyResultEnum>;

export type MatchedBy =
  | "sha256"
  | "watermark"
  | "phash"
  | "certId"
  | "filename";

export interface ImageVerifyAnalysis {
  watermark: { found: boolean; confidence: number };
  visualDistance: number;
  tamperScore: number;
  changedPercent: number;
  changedRegions: number;
  changedCells: Array<{ x: number; y: number }>;
  gridSize: number;
  width: number;
  height: number;
  matchedBy?: MatchedBy;
  reason?: string;
  /** Localized classifier label from classifyImageChange(). */
  changeClass?: ImageChangeClass;
  maxCellScore?: number;
  largestCluster?: Pick<ChangedCellCluster, "size" | "score"> & {
    cells?: Array<{ x: number; y: number }>;
  };
  /** Pixel-stage bounding boxes (original coordinates). */
  localizedRegions?: LocalizedRegion[];
  /** True when pixel second-stage contributed to the verdict. */
  pixelStageUsed?: boolean;
}

export interface VerifyResponse {
  result: VerifyResultType;
  uploadedSha256: string;
  certId?: string;
  certificate?: ReturnType<typeof publicCertificateView>;
  diff?: DiffResult;
  analysis?: AnalysisResult;
  explanation?: PlainLanguageResult;
  newerVersion?: { certId: string; version: number } | null;
  message: string;
  signatureValid?: boolean;
  imageAnalysis?: ImageVerifyAnalysis;
  /** True when signatureVersion < 2 (analysis fields not covered by signature). */
  legacyRecord?: boolean;
  /** When REVOKED: whether log-bound reason/time verified. */
  detailsVerified?: boolean;
  /** Transparency-log integrity for this verification. */
  logIntegrity?: LogIntegrity;
}

async function finalizeVerifyResponse(
  response: VerifyResponse,
  revocation?: RevocationLogCheck | null,
): Promise<VerifyResponse> {
  const chainStatus = await getLogChainStatus();
  const certLogIntegrity =
    revocation?.logIntegrity && revocation.logIntegrity !== "OK"
      ? revocation.logIntegrity
      : null;
  const next = applyLogIntegrityToVerifyResponse(response, {
    certLogIntegrity,
    chainStatus,
  });
  if (next.logIntegrity === "BROKEN" && next.analysis) {
    return {
      ...next,
      explanation: explainAnalysis(
        next.analysis as Parameters<typeof explainAnalysis>[0],
        { revoked: next.result === "REVOKED" },
      ),
    };
  }
  return next;
}

function legacyFlag(cert: Certificate): boolean {
  return isLegacySignatureVersion(cert.signatureVersion);
}

function signatureInvalidResponse(
  cert: Certificate,
  uploadedSha256: string,
): VerifyResponse {
  return {
    result: "TAMPERED",
    uploadedSha256,
    certId: cert.certId,
    signatureValid: false,
    legacyRecord: legacyFlag(cert),
    message:
      "Certificate record signature is invalid — the record may have been altered.",
  };
}

function storedIntegrityUnavailable(
  cert: Certificate,
  uploadedSha256: string,
  signatureValid: boolean,
): VerifyResponse {
  const analysis: AnalysisResult = {
    verdict: Verdict.ANALYSIS_UNAVAILABLE,
    confidence: "LOW",
    checks: [
      {
        name: "stored-file-integrity",
        status: "FAILED",
        detail:
          "The stored certified original failed its integrity check; this certificate cannot be used for comparison.",
      },
    ],
    changes: [],
    notChecked: ["content-comparison"],
  };
  return {
    result: "ANALYSIS_UNAVAILABLE",
    uploadedSha256,
    certId: cert.certId,
    certificate: publicCertificateView(cert),
    analysis,
    explanation: explainAnalysis(analysis),
    signatureValid,
    legacyRecord: legacyFlag(cert),
    message:
      "The stored certified original failed its integrity check; this certificate cannot be used for comparison.",
  };
}

function mapAnalysisVerdict(v: Verdict): VerifyResultType {
  switch (v) {
    case Verdict.AUTHENTIC:
      return "AUTHENTIC";
    case Verdict.MODIFIED_FORMAT_ONLY:
      return "MODIFIED_FORMAT_ONLY";
    case Verdict.TAMPERED:
      return "TAMPERED";
    case Verdict.ANALYSIS_UNAVAILABLE:
      return "ANALYSIS_UNAVAILABLE";
    case Verdict.NOT_FOUND:
      return "NOT_FOUND";
    default:
      return "TAMPERED";
  }
}

function parseCellSignatures(cert: Certificate): CellSignature[] | null {
  if (!cert.cellSignatures) return null;
  try {
    return JSON.parse(cert.cellSignatures) as CellSignature[];
  } catch {
    return null;
  }
}

function analysisFromImageVerdict(
  result: VerifyResultType,
  checks: CheckResult[],
  detail?: string,
): AnalysisResult {
  const verdict =
    result === "AUTHENTIC"
      ? Verdict.AUTHENTIC
      : result === "MODIFIED_REENCODED" || result === "MODIFIED_FORMAT_ONLY"
        ? Verdict.MODIFIED_FORMAT_ONLY
        : result === "ANALYSIS_UNAVAILABLE"
          ? Verdict.ANALYSIS_UNAVAILABLE
          : Verdict.TAMPERED;
  return {
    verdict,
    confidence:
      result === "ANALYSIS_UNAVAILABLE"
        ? "LOW"
        : result === "MODIFIED_REENCODED"
          ? "MEDIUM"
          : "HIGH",
    checks,
    changes: detail
      ? [{ description: detail, kind: "image" }]
      : [],
    notChecked: [],
  };
}

function withImageAnalysisPayload(
  response: Omit<VerifyResponse, "analysis" | "explanation">,
  extraChecks: CheckResult[],
  detail?: string,
): VerifyResponse {
  if (extraChecks.length === 0 && response.result !== "ANALYSIS_UNAVAILABLE") {
    return response;
  }
  const checks: CheckResult[] =
    extraChecks.length > 0
      ? extraChecks
      : response.analysis?.checks ?? [
          {
            name: "image-content",
            status:
              response.result === "TAMPERED"
                ? "FAILED"
                : response.result === "ANALYSIS_UNAVAILABLE"
                  ? "NOT_CHECKED"
                  : "PASSED",
            detail,
          },
        ];
  const analysis = analysisFromImageVerdict(response.result, checks, detail);
  return {
    ...response,
    analysis,
    explanation: explainAnalysis(analysis, {
      revoked: response.result === "REVOKED",
    }),
  };
}

interface ImageVerifyOptions {
  extraChecks?: CheckResult[];
  /** Structural / overlay force — verdict cannot be better than TAMPERED. */
  forceTamperedReason?: string;
  forceTamperedRegions?: LocalizedRegion[];
  /**
   * When false (PDF with extra image draws / overlays), refuse MODIFIED_REENCODED
   * even if pixels match.
   */
  allowModifiedReencoded?: boolean;
}

/**
 * Verify an image certificate against already-decoded (or PDF-extracted) pixels.
 */
async function verifyImagePixelsAgainstCert(
  cert: Certificate,
  uploadedPixels: PixelBuffer,
  uploadedSha256: string,
  matchedBy: MatchedBy,
  watermarkInfo: { found: boolean; confidence: number },
  signatureValid: boolean,
  revocation: RevocationLogCheck,
  options: ImageVerifyOptions = {},
): Promise<VerifyResponse> {
  const {
    extraChecks = [],
    forceTamperedReason,
    forceTamperedRegions,
    allowModifiedReencoded = true,
  } = options;
  const config = getConfig();

  const origW = cert.width ?? uploadedPixels.width;
  const origH = cert.height ?? uploadedPixels.height;

  const baseAnalysis: ImageVerifyAnalysis = {
    watermark: watermarkInfo,
    visualDistance: 0,
    tamperScore: 0,
    changedPercent: 0,
    changedRegions: 0,
    changedCells: [],
    gridSize: cert.gridSize || config.imageGridSize,
    width: uploadedPixels.width,
    height: uploadedPixels.height,
    matchedBy,
  };

  const wrap = (
    response: Omit<VerifyResponse, "analysis" | "explanation">,
    detail?: string,
  ) =>
    finalizeVerifyResponse(
      withImageAnalysisPayload(response, extraChecks, detail),
      revocation,
    );

  // Aspect ratio differs → TAMPERED, skip cell comparison
  if (aspectDiffers(origW, origH, uploadedPixels.width, uploadedPixels.height)) {
    await logVerification(cert.certId, "TAMPERED", uploadedSha256);
    return wrap(
      {
        result: "TAMPERED",
        uploadedSha256,
        certId: cert.certId,
        certificate: publicCertificateView(cert),
        signatureValid,
        legacyRecord: legacyFlag(cert),
        message:
          "Image dimensions differ from the certified original (aspect ratio changed).",
        imageAnalysis: {
          ...baseAnalysis,
          reason: "dimensions differ",
        },
      },
      "dimensions differ",
    );
  }

  // Same aspect, different size → resize upload to original first
  let comparePixels = uploadedPixels;
  if (
    uploadedPixels.width !== origW ||
    uploadedPixels.height !== origH
  ) {
    comparePixels = await resizePixels(uploadedPixels, origW, origH);
  }

  const origCells = parseCellSignatures(cert);
  const gridSize = cert.gridSize || config.imageGridSize;
  const uploadCells = cellSignatures(comparePixels, gridSize);

  let comparison;
  let storedPixelsForPixelStage: PixelBuffer | null = null;
  if (origCells && origCells.length === gridSize * gridSize) {
    comparison = compareCells(origCells, uploadCells, gridSize, {
      hammingThreshold: config.cellHammingThreshold,
      lumaDeltaThreshold: config.cellLumaDeltaThreshold,
      outlierK: config.outlierK,
      outlierAbsFloor: config.outlierAbsFloor,
    });
  } else {
    // Fallback: recompute from stored certified file
    try {
      const stored = await readVerifiedStoredFile(cert);
      storedPixelsForPixelStage = await decodeImage(stored);
      const recomputed = cellSignatures(storedPixelsForPixelStage, gridSize);
      comparison = compareCells(recomputed, uploadCells, gridSize, {
        hammingThreshold: config.cellHammingThreshold,
        lumaDeltaThreshold: config.cellLumaDeltaThreshold,
        outlierK: config.outlierK,
        outlierAbsFloor: config.outlierAbsFloor,
      });
    } catch (err) {
      if (err instanceof AppError && err.code === "STORED_FILE_INTEGRITY") {
        await logVerification(cert.certId, "ANALYSIS_UNAVAILABLE", uploadedSha256);
        return finalizeVerifyResponse(
          storedIntegrityUnavailable(cert, uploadedSha256, signatureValid),
          revocation,
        );
      }
      console.error("[verifyImageAgainstCert] stored decode failed", err);
      const analysis: AnalysisResult = {
        verdict: Verdict.ANALYSIS_UNAVAILABLE,
        confidence: "LOW",
        checks: [
          ...extraChecks,
          {
            name: "image-cells",
            status: "NOT_CHECKED",
            detail: "Could not decode the stored certified image for comparison",
          },
        ],
        changes: [],
        notChecked: ["cell-signatures", "visual-comparison"],
      };
      await logVerification(cert.certId, "ANALYSIS_UNAVAILABLE", uploadedSha256);
      return finalizeVerifyResponse(
        {
          result: "ANALYSIS_UNAVAILABLE",
          uploadedSha256,
          certId: cert.certId,
          certificate: publicCertificateView(cert),
          analysis,
          explanation: explainAnalysis(analysis),
          signatureValid,
          legacyRecord: legacyFlag(cert),
          message:
            "Matched an image certificate, but could not decode the stored certified file for comparison.",
          imageAnalysis: {
            ...baseAnalysis,
            reason: "stored image decode failed",
          },
        },
        revocation,
      );
    }
  }

  let classified = classifyImageChange(comparison, {
    tamperScoreAlert: config.tamperScoreAlert,
    cellStrongHamming: config.cellStrongHamming,
    cellStrongLuma: config.cellStrongLuma,
    tamperMinClusterCells: config.tamperMinClusterCells,
    globalChangeMinPercent: config.globalChangeMinPercent,
    outlierK: config.outlierK,
    outlierAbsFloor: config.outlierAbsFloor,
  });

  const largest = comparison.clusters[0];
  const imageAnalysis: ImageVerifyAnalysis = {
    ...baseAnalysis,
    visualDistance: comparison.visualDistance,
    tamperScore: comparison.tamperScore,
    changedPercent: comparison.changedPercent,
    changedRegions: comparison.changedCells.length,
    changedCells: comparison.changedCells,
    gridSize: comparison.gridSize,
    width: comparePixels.width,
    height: comparePixels.height,
    reason: classified.reason,
    changeClass: classified.classification,
    maxCellScore: comparison.maxCellScore,
    largestCluster: largest
      ? { size: largest.size, score: largest.score, cells: largest.cells }
      : undefined,
  };

  // Pixel second stage: catch sub-cell / JPEG-softened edits the cell
  // classifier labels GLOBAL_ADJUSTMENT or REENCODED. Photometric alignment
  // + tile normalisation in detectLocalizedPixelTamper absorb global shifts;
  // only skip when cells already decided TAMPERED.
  if (classified.classification !== "TAMPERED") {
    try {
      if (!storedPixelsForPixelStage) {
        const stored = await readVerifiedStoredFile(cert);
        storedPixelsForPixelStage = await decodeImage(stored);
        if (
          storedPixelsForPixelStage.width !== origW ||
          storedPixelsForPixelStage.height !== origH
        ) {
          storedPixelsForPixelStage = await resizePixels(
            storedPixelsForPixelStage,
            origW,
            origH,
          );
        }
      }
      const pixel = await detectLocalizedPixelTamper(
        storedPixelsForPixelStage,
        comparePixels,
        {
          minRegionArea: config.pixelMinRegionArea,
          outlierK: config.outlierK,
        },
      );
      imageAnalysis.pixelStageUsed = true;
      if (pixel.tampered) {
        classified = {
          classification: "TAMPERED",
          reason: pixel.reason,
        };
        imageAnalysis.changeClass = "TAMPERED";
        imageAnalysis.reason = pixel.reason;
        imageAnalysis.localizedRegions = pixel.regions;
      } else {
        imageAnalysis.reason = `${classified.reason}; ${pixel.reason}`;
      }
    } catch (err) {
      if (err instanceof AppError && err.code === "STORED_FILE_INTEGRITY") {
        await logVerification(cert.certId, "ANALYSIS_UNAVAILABLE", uploadedSha256);
        return finalizeVerifyResponse(
          storedIntegrityUnavailable(cert, uploadedSha256, signatureValid),
          revocation,
        );
      }
      console.error("[verifyImageAgainstCert] pixel stage failed", err);
      imageAnalysis.reason = `${classified.reason}; pixel stage unavailable (stored file unreadable)`;
    }
  }

  // PDF overlays / structural rules: cannot report better than TAMPERED.
  // Prefer the overlay reason even when cells already flagged tampering —
  // that is the user-visible explanation for PDF markup / drawn-over attacks.
  if (forceTamperedReason) {
    classified = {
      classification: "TAMPERED",
      reason: forceTamperedReason,
    };
    imageAnalysis.changeClass = "TAMPERED";
    imageAnalysis.reason = forceTamperedReason;
    if (forceTamperedRegions?.length) {
      imageAnalysis.localizedRegions = forceTamperedRegions;
    }
  } else if (
    !allowModifiedReencoded &&
    classified.classification !== "TAMPERED"
  ) {
    classified = {
      classification: "TAMPERED",
      reason: PDF_OVERLAY_TAMPER_REASON,
    };
    imageAnalysis.changeClass = "TAMPERED";
    imageAnalysis.reason = classified.reason;
  }

  if (revocation.revoked) {
    await logVerification(cert.certId, "REVOKED", uploadedSha256);
    const revokeNote = revokeDisplayMessage(revocation, cert.revokeReason);
    return wrap({
      result: "REVOKED",
      uploadedSha256,
      certId: cert.certId,
      certificate: publicCertificateView(cert),
      signatureValid,
      legacyRecord: legacyFlag(cert),
      detailsVerified: revocation.detailsVerified,
      message: revocation.detailsVerified
        ? "Certificate has been revoked. Do not treat this file as currently certified."
        : `${revokeNote}. Do not treat this file as currently certified.`,
      imageAnalysis,
    });
  }

  if (classified.classification === "TAMPERED") {
    await logVerification(cert.certId, "TAMPERED", uploadedSha256);
    return wrap(
      {
        result: "TAMPERED",
        uploadedSha256,
        certId: cert.certId,
        certificate: publicCertificateView(cert),
        signatureValid,
        legacyRecord: legacyFlag(cert),
        message: `Image has been tampered with. ${comparison.changedCells.length} cell(s) differ (${comparison.changedPercent.toFixed(1)}% of grid). ${classified.reason}`,
        imageAnalysis,
      },
      classified.reason,
    );
  }

  if (classified.classification === "GLOBAL_ADJUSTMENT") {
    await logVerification(cert.certId, "MODIFIED_REENCODED", uploadedSha256);
    return wrap({
      result: "MODIFIED_REENCODED",
      uploadedSha256,
      certId: cert.certId,
      certificate: publicCertificateView(cert),
      signatureValid,
      legacyRecord: legacyFlag(cert),
      message:
        "Whole-image adjustment detected (brightness/contrast/filter). Not considered content tampering.",
      imageAnalysis,
    });
  }

  // UNCHANGED | REENCODED
  await logVerification(cert.certId, "MODIFIED_REENCODED", uploadedSha256);
  return wrap({
    result: "MODIFIED_REENCODED",
    uploadedSha256,
    certId: cert.certId,
    certificate: publicCertificateView(cert),
    signatureValid,
    legacyRecord: legacyFlag(cert),
    message:
      "Image matches the certified visual content (re-encoded or lightly processed). Not considered tampered.",
    imageAnalysis,
  });
}

type PdfImageExtractOk = Extract<
  Awaited<ReturnType<typeof extractImagePixelsFromPdf>>,
  { ok: true }
>;

function formatConversionDetail(extracted: PdfImageExtractOk): string {
  const outside = extracted.overlays.filter((o) => !o.overlapsImage);
  let detail =
    "Uploaded as PDF; compared the visible page content in the image area";
  if (outside.length > 0) {
    const kinds = [...new Set(outside.map((o) => o.kind))].join(", ");
    detail += ` (also has ${kinds} outside the image area)`;
  }
  return detail;
}

async function diagnosePdfImageOverlays(
  extracted: PdfImageExtractOk,
  targetW: number,
  targetH: number,
): Promise<{
  forceTamperedReason?: string;
  forceTamperedRegions?: LocalizedRegion[];
  overlayCheck?: CheckResult;
}> {
  const overlapping = extracted.overlays.filter((o) => o.overlapsImage);
  let forceTamperedReason: string | undefined;
  let forceTamperedRegions: LocalizedRegion[] | undefined;
  let overlayCheck: CheckResult | undefined;

  if (overlapping.length > 0 || extracted.imageDrawCount !== 1) {
    const details = overlapping.map((o) => o.detail).join("; ");
    overlayCheck = {
      name: "pdf-overlay",
      status: "FAILED",
      detail:
        overlapping.length > 0
          ? `Visible content overlaps the image area: ${details || "unknown"}`
          : `PDF has ${extracted.imageDrawCount} image draws; expected exactly one`,
    };
    forceTamperedReason = PDF_OVERLAY_TAMPER_REASON;
  }

  if (extracted.embeddedPixels) {
    try {
      let embedded = extracted.embeddedPixels;
      if (embedded.width !== targetW || embedded.height !== targetH) {
        embedded = await resizePixels(embedded, targetW, targetH);
      }
      let rendered = extracted.pixels;
      if (rendered.width !== targetW || rendered.height !== targetH) {
        rendered = await resizePixels(rendered, targetW, targetH);
      }
      const pixel = await detectLocalizedPixelTamper(embedded, rendered, {
        minRegionArea: getConfig().pixelMinRegionArea,
        outlierK: getConfig().outlierK,
      });
      if (pixel.tampered) {
        forceTamperedReason = PDF_OVERLAY_TAMPER_REASON;
        forceTamperedRegions = pixel.regions;
        if (!overlayCheck) {
          overlayCheck = {
            name: "pdf-overlay",
            status: "FAILED",
            detail: PDF_OVERLAY_TAMPER_REASON,
          };
        }
      }
    } catch (err) {
      console.error("[diagnosePdfImageOverlays] embedded vs rendered failed", err);
    }
  }

  return { forceTamperedReason, forceTamperedRegions, overlayCheck };
}

/**
 * Image-certificate verify when the upload is a PDF (Preview export, etc.).
 * Always uses rendered page pixels (annotations painted); embedded XObject
 * is diagnostic only.
 */
async function verifyImageCertFromPdf(
  cert: Certificate,
  uploadedBytes: Buffer,
  uploadedSha256: string,
  matchedBy: MatchedBy,
  watermarkInfo: { found: boolean; confidence: number },
  signatureValid: boolean,
  revocation: RevocationLogCheck,
): Promise<VerifyResponse> {
  const extracted = await extractImagePixelsFromPdf(uploadedBytes, {
    width: cert.width,
    height: cert.height,
  });
  if (!extracted.ok) {
    const analysis: AnalysisResult = {
      verdict: Verdict.ANALYSIS_UNAVAILABLE,
      confidence: "LOW",
      checks: [
        {
          name: "format-conversion",
          status: "FAILED",
          detail: PDF_IMAGE_UNAVAILABLE_MESSAGE,
        },
      ],
      changes: [],
      notChecked: ["image-content"],
    };
    await logVerification(cert.certId, "ANALYSIS_UNAVAILABLE", uploadedSha256);
    return finalizeVerifyResponse(
      {
        result: "ANALYSIS_UNAVAILABLE",
        uploadedSha256,
        certId: cert.certId,
        certificate: publicCertificateView(cert),
        analysis,
        explanation: explainAnalysis(analysis),
        signatureValid,
        legacyRecord: legacyFlag(cert),
        message: PDF_IMAGE_UNAVAILABLE_MESSAGE,
        imageAnalysis: {
          watermark: watermarkInfo,
          visualDistance: 0,
          tamperScore: 0,
          changedPercent: 0,
          changedRegions: 0,
          changedCells: [],
          gridSize: cert.gridSize || getConfig().imageGridSize,
          width: cert.width ?? 0,
          height: cert.height ?? 0,
          matchedBy,
          reason: extracted.reason,
        },
      },
      revocation,
    );
  }

  const targetW = cert.width ?? extracted.pixels.width;
  const targetH = cert.height ?? extracted.pixels.height;
  const diagnosis = await diagnosePdfImageOverlays(
    extracted,
    targetW,
    targetH,
  );

  const extraChecks: CheckResult[] = [
    {
      name: "format-conversion",
      status: "PASSED",
      detail: formatConversionDetail(extracted),
    },
  ];
  if (diagnosis.overlayCheck) {
    extraChecks.push(diagnosis.overlayCheck);
  }

  return verifyImagePixelsAgainstCert(
    cert,
    extracted.pixels,
    uploadedSha256,
    matchedBy,
    watermarkInfo,
    signatureValid,
    revocation,
    {
      extraChecks,
      forceTamperedReason: diagnosis.forceTamperedReason,
      forceTamperedRegions: diagnosis.forceTamperedRegions,
      allowModifiedReencoded:
        extracted.cleanSingleImage && !diagnosis.forceTamperedReason,
    },
  );
}

/**
 * Resolve upload bytes (including PDF wrappers / unsupported formats) then
 * verify against an image certificate. Never falls through to binary diff.
 */
async function verifyImageAgainstCert(
  cert: Certificate,
  uploadedBytes: Buffer,
  uploadedSha256: string,
  matchedBy: MatchedBy,
  watermarkInfo: { found: boolean; confidence: number },
): Promise<VerifyResponse> {
  const signatureValid = await checkRecordSignature(cert);
  if (!signatureValid) {
    await logVerification(cert.certId, "TAMPERED", uploadedSha256);
    return finalizeVerifyResponse(signatureInvalidResponse(cert, uploadedSha256));
  }

  const revocation = await checkCertificateRevocation(cert);

  if (isPdfBuffer(uploadedBytes)) {
    return verifyImageCertFromPdf(
      cert,
      uploadedBytes,
      uploadedSha256,
      matchedBy,
      watermarkInfo,
      signatureValid,
      revocation,
    );
  }

  const format = detectBufferFormat(uploadedBytes);
  if (format !== "unknown" && !isSharpDecodableImageFormat(format)) {
    const label = formatDisplayName(format);
    const message = `Unsupported image format (${label}). Convert to PNG, JPEG, or WebP and try again.`;
    const analysis: AnalysisResult = {
      verdict: Verdict.ANALYSIS_UNAVAILABLE,
      confidence: "LOW",
      checks: [
        {
          name: "format-conversion",
          status: "FAILED",
          detail: message,
        },
      ],
      changes: [],
      notChecked: ["image-content"],
    };
    await logVerification(cert.certId, "ANALYSIS_UNAVAILABLE", uploadedSha256);
    return finalizeVerifyResponse(
      {
        result: "ANALYSIS_UNAVAILABLE",
        uploadedSha256,
        certId: cert.certId,
        certificate: publicCertificateView(cert),
        analysis,
        explanation: explainAnalysis(analysis),
        signatureValid,
        legacyRecord: legacyFlag(cert),
        message,
        imageAnalysis: {
          watermark: watermarkInfo,
          visualDistance: 0,
          tamperScore: 0,
          changedPercent: 0,
          changedRegions: 0,
          changedCells: [],
          gridSize: cert.gridSize || getConfig().imageGridSize,
          width: cert.width ?? 0,
          height: cert.height ?? 0,
          matchedBy,
          reason: `unsupported format: ${label}`,
        },
      },
      revocation,
    );
  }

  let uploadedPixels: PixelBuffer;
  try {
    uploadedPixels = await decodeImage(uploadedBytes);
  } catch (err) {
    const label =
      format === "unknown" ? "unknown" : formatDisplayName(format);
    const message = `Unsupported image format (${label}). Convert to PNG, JPEG, or WebP and try again.`;
    const analysis: AnalysisResult = {
      verdict: Verdict.ANALYSIS_UNAVAILABLE,
      confidence: "LOW",
      checks: [
        {
          name: "format-conversion",
          status: "FAILED",
          detail: `${message}${err instanceof Error ? ` (${err.message})` : ""}`,
        },
      ],
      changes: [],
      notChecked: ["image-content"],
    };
    await logVerification(cert.certId, "ANALYSIS_UNAVAILABLE", uploadedSha256);
    return finalizeVerifyResponse(
      {
        result: "ANALYSIS_UNAVAILABLE",
        uploadedSha256,
        certId: cert.certId,
        certificate: publicCertificateView(cert),
        analysis,
        explanation: explainAnalysis(analysis),
        signatureValid,
        legacyRecord: legacyFlag(cert),
        message,
        imageAnalysis: {
          watermark: watermarkInfo,
          visualDistance: 0,
          tamperScore: 0,
          changedPercent: 0,
          changedRegions: 0,
          changedCells: [],
          gridSize: cert.gridSize || getConfig().imageGridSize,
          width: cert.width ?? 0,
          height: cert.height ?? 0,
          matchedBy,
          reason: "decode failed",
        },
      },
      revocation,
    );
  }

  return verifyImagePixelsAgainstCert(
    cert,
    uploadedPixels,
    uploadedSha256,
    matchedBy,
    watermarkInfo,
    signatureValid,
    revocation,
  );
}

async function resolveImageCertificate(
  uploadedBytes: Buffer,
  certIdField?: string | null,
  filename?: string,
): Promise<{
  cert: Certificate | null;
  matchedBy?: MatchedBy;
  watermark: { found: boolean; confidence: number };
}> {
  const config = getConfig();
  const pixels = await decodeImage(uploadedBytes);
  const extracted = extract(pixels, {
    key: config.watermarkKey,
    step: config.watermarkQimStep,
  });

  const watermark = {
    found:
      extracted.confidence >= config.watermarkConfidenceMin &&
      Boolean(extracted.payload),
    confidence: extracted.confidence,
  };

  // High-confidence watermark → lookup by token (legacy ID or compact prefix)
  if (watermark.found && extracted.payload) {
    const cert =
      (await getCertificateByWatermarkToken(extracted.payload)) ??
      (await getCertificateById(extracted.payload));
    if (cert) {
      return { cert, matchedBy: "watermark", watermark };
    }
  }

  // Closest phash among certificates
  const uploadPhash = phash64(pixels);
  const closest = await findClosestByPhash(uploadPhash, config.phashMatchMax);
  if (closest) {
    return {
      cert: closest.cert,
      matchedBy: "phash",
      watermark,
    };
  }

  // Fallback: explicit certId / filename
  const fromFilename = parseCertIdFromFilename(filename || "");
  const certId =
    (certIdField && certIdField.trim()) || fromFilename || undefined;
  if (certId) {
    const cert = await getCertificateById(certId);
    if (cert) {
      return {
        cert,
        matchedBy: fromFilename && !certIdField ? "filename" : "certId",
        watermark,
      };
    }
  }

  return { cert: null, watermark };
}

export async function verifyUpload(
  file: File,
  certIdField?: string | null,
): Promise<VerifyResponse> {
  const hash = await hashUploadedFile(file);
  const uploadedSha256 = hash.sha256;
  const uploadedBytes = Buffer.from(await file.arrayBuffer());
  const mimeGuess = file.type || "";
  const isImage = isCertifiableImage(mimeGuess, file.name || "");

  // 1. Exact content match → AUTHENTIC (or REVOKED)
  const byHash = await getCertificateBySha256(uploadedSha256);
  if (byHash) {
    const signatureValid = await checkRecordSignature(byHash);
    if (!signatureValid) {
      await logVerification(byHash.certId, "TAMPERED", uploadedSha256);
      return finalizeVerifyResponse(signatureInvalidResponse(byHash, uploadedSha256));
    }

    const revocation = await checkCertificateRevocation(byHash);
    if (revocation.revoked) {
      await logVerification(byHash.certId, "REVOKED", uploadedSha256);
      const analysis: AnalysisResult = {
        verdict: Verdict.AUTHENTIC,
        confidence: "HIGH",
        checks: [{ name: "sha256", status: "PASSED" }],
        changes: [],
        notChecked: [],
      };
      const revokeNote = revokeDisplayMessage(revocation, byHash.revokeReason);
      return finalizeVerifyResponse(
        {
          result: "REVOKED",
          uploadedSha256,
          certId: byHash.certId,
          certificate: publicCertificateView(byHash),
          analysis,
          explanation: explainAnalysis(analysis, { revoked: true }),
          signatureValid: true,
          legacyRecord: legacyFlag(byHash),
          detailsVerified: revocation.detailsVerified,
          message: revocation.detailsVerified
            ? "Certificate has been revoked. Bytes match, but this certificate is no longer valid."
            : `${revokeNote}. Bytes match, but this certificate is no longer valid.`,
        },
        revocation,
      );
    }

    await logVerification(byHash.certId, "AUTHENTIC", uploadedSha256);

    let imageAnalysis: ImageVerifyAnalysis | undefined;
    if (byHash.imagePhash && isImage) {
      try {
        const pixels = await decodeImage(uploadedBytes);
        const extracted = extract(pixels, {
          key: getConfig().watermarkKey,
          step: getConfig().watermarkQimStep,
        });
        imageAnalysis = {
          watermark: {
            found: extracted.confidence >= getConfig().watermarkConfidenceMin,
            confidence: extracted.confidence,
          },
          visualDistance: 0,
          tamperScore: 0,
          changedPercent: 0,
          changedRegions: 0,
          changedCells: [],
          gridSize: byHash.gridSize,
          width: pixels.width,
          height: pixels.height,
          matchedBy: "sha256",
        };
      } catch {
        // ignore analysis failures on authentic path
      }
    }

    const analysis: AnalysisResult = {
      verdict: Verdict.AUTHENTIC,
      confidence: "HIGH",
      checks: [{ name: "sha256", status: "PASSED", detail: "Exact hash match" }],
      changes: [],
      notChecked: [],
    };
    const newest = await findNewestVersion(byHash.certId);
    const newerVersion =
      newest && newest.certId !== byHash.certId
        ? { certId: newest.certId, version: newest.version }
        : null;

    return finalizeVerifyResponse(
      {
        result: "AUTHENTIC",
        uploadedSha256,
        certId: byHash.certId,
        certificate: publicCertificateView(byHash),
        analysis,
        explanation: explainAnalysis(analysis),
        newerVersion,
        signatureValid: true,
        legacyRecord: legacyFlag(byHash),
        message: newerVersion
          ? `File is authentic for this version, but a newer version exists (${newerVersion.certId}).`
          : "File is authentic. Content hash matches the certified original.",
        imageAnalysis,
      },
      revocation,
    );
  }

  // Image pipeline (when upload is a certifiable image)
  if (isImage) {
    try {
      const resolved = await resolveImageCertificate(
        uploadedBytes,
        certIdField,
        file.name,
      );

      if (!resolved.cert) {
        await logVerification(null, "NOT_FOUND", uploadedSha256);
        return finalizeVerifyResponse({
          result: "NOT_FOUND",
          uploadedSha256,
          message:
            "No matching image certificate found (watermark / perceptual hash).",
          imageAnalysis: {
            watermark: resolved.watermark,
            visualDistance: 0,
            tamperScore: 0,
            changedPercent: 0,
            changedRegions: 0,
            changedCells: [],
            gridSize: getConfig().imageGridSize,
            width: 0,
            height: 0,
          },
        });
      }

      // Only run the image pipeline against image certificates.
      // A certId may point at a PDF/DOCX cert — use the generic path instead.
      if (resolved.cert.imagePhash) {
        return await verifyImageAgainstCert(
          resolved.cert,
          uploadedBytes,
          uploadedSha256,
          resolved.matchedBy ?? "phash",
          resolved.watermark,
        );
      }
      // Non-image cert matched by ID while upload is an image → fall through
    } catch (err) {
      if (err instanceof AppError) throw err;
      // Fall through to generic path if decode / watermark fails
      console.error("[verifyUpload] image pipeline failed, falling back", err);
    }
  }

  // 2. Non-image: resolve certId from field or filename
  const fromFilename = parseCertIdFromFilename(file.name || "");
  const certId =
    (certIdField && certIdField.trim()) || fromFilename || undefined;

  if (certId) {
    const cert = await getCertificateById(certId);
    if (cert) {
      const signatureValid = await checkRecordSignature(cert);
      if (!signatureValid) {
        await logVerification(cert.certId, "TAMPERED", uploadedSha256);
        return finalizeVerifyResponse(signatureInvalidResponse(cert, uploadedSha256));
      }

      const revocation = await checkCertificateRevocation(cert);

      // Image cert + non-image upload (e.g. PDF of the certified PNG): never
      // fall through to binary diff — that produces misleading dimensions.
      if (cert.imagePhash) {
        return await verifyImageAgainstCert(
          cert,
          uploadedBytes,
          uploadedSha256,
          "certId",
          { found: false, confidence: 0 },
        );
      }

      let originalBuf: Buffer;
      try {
        originalBuf = await readVerifiedStoredFile(cert);
      } catch (err) {
        if (err instanceof AppError && err.code === "STORED_FILE_INTEGRITY") {
          await logVerification(
            cert.certId,
            "ANALYSIS_UNAVAILABLE",
            uploadedSha256,
          );
          return finalizeVerifyResponse(
            storedIntegrityUnavailable(cert, uploadedSha256, true),
            revocation,
          );
        }
        throw err;
      }

      let chunkHashes: string[] | undefined;
      try {
        chunkHashes = JSON.parse(cert.chunkHashes) as string[];
      } catch {
        chunkHashes = undefined;
      }

      const analysis = await analyzePair({
        original: originalBuf,
        uploaded: uploadedBytes,
        originalName: cert.originalName,
        mimeType: cert.mimeType,
      });

      const diff = await diffFiles({
        original: originalBuf,
        uploaded: uploadedBytes,
        originalName: cert.originalName,
        mimeType: cert.mimeType,
        chunkHashes,
      });

      if (revocation.revoked) {
        await logVerification(cert.certId, "REVOKED", uploadedSha256);
        const revokeNote = revokeDisplayMessage(revocation, cert.revokeReason);
        return finalizeVerifyResponse(
          {
            result: "REVOKED",
            uploadedSha256,
            certId: cert.certId,
            certificate: publicCertificateView(cert),
            analysis,
            explanation: explainAnalysis(analysis, { revoked: true }),
            signatureValid: true,
            legacyRecord: legacyFlag(cert),
            detailsVerified: revocation.detailsVerified,
            message: revocation.detailsVerified
              ? "Certificate has been revoked. Do not treat this file as currently certified."
              : `${revokeNote}. Do not treat this file as currently certified.`,
          },
          revocation,
        );
      }

      const result = mapAnalysisVerdict(analysis.verdict);
      await logVerification(cert.certId, result, uploadedSha256);
      const newest = await findNewestVersion(cert.certId);
      const newerVersion =
        newest && newest.certId !== cert.certId
          ? { certId: newest.certId, version: newest.version }
          : null;
      return finalizeVerifyResponse(
        {
          result,
          uploadedSha256,
          certId: cert.certId,
          certificate: publicCertificateView(cert),
          diff,
          analysis,
          explanation: explainAnalysis(analysis),
          newerVersion,
          signatureValid: true,
          legacyRecord: legacyFlag(cert),
          message: messageForAnalysis(analysis),
        },
        revocation,
      );
    }
  }

  // 3. NOT_FOUND
  await logVerification(certId ?? null, "NOT_FOUND", uploadedSha256);
  return finalizeVerifyResponse({
    result: "NOT_FOUND",
    uploadedSha256,
    certId,
    message: certId
      ? `No certificate found for ID "${certId}", and the file hash is not registered. Check the certificate ID.`
      : "File hash not found. Provide a certificate ID (or upload a certified filename) to check for tampering.",
  });
}

async function logVerification(
  certId: string | null,
  result: VerifyResultType,
  uploadedSha256: string,
) {
  await prisma.verificationLog.create({
    data: { certId, result, uploadedSha256 },
  });
}

function messageForAnalysis(analysis: AnalysisResult): string {
  switch (analysis.verdict) {
    case Verdict.AUTHENTIC:
      return "File is authentic. Content hash matches the certified original.";
    case Verdict.MODIFIED_FORMAT_ONLY:
      return "Content appears unchanged, but the file format or metadata differs from the certified original.";
    case Verdict.TAMPERED:
      return "File does not match the certified original. Content has been tampered with or altered.";
    case Verdict.ANALYSIS_UNAVAILABLE:
      return "Could not fully analyze this file. Some checks were unavailable.";
    default:
      return "Verification complete.";
  }
}
