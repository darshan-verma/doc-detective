import { createHash } from "crypto";
import path from "path";
import { pathToFileURL } from "url";
import pixelmatch from "pixelmatch";
import { extractPdfPages } from "../../diff/pdf";
import { smartLineDiff } from "../../diff/text";
import { analysisConfig } from "../config";
import {
  CONTENT_CHECK_NAMES,
  FORMAT_CHECK_NAMES,
  Verdict,
  type AnalysisChange,
  type AnalysisResult,
  type Analyzer,
  type CheckResult,
  type VisualPageDiff,
} from "../types";
import { boundingBoxesFromDiffMask } from "../visual-boxes";
import { deriveVerdict, sha256Buffer, unavailableResult } from "../verdict";

interface PdfStructure {
  pageCount: number;
  pageSizes: Array<{ width: number; height: number }>;
  meta: Record<string, string>;
  annotations: Array<{ page: number; name: string; value: string }>;
  formFields: Array<{ name: string; value: string }>;
  fontNames: string[];
  hasJavaScript: boolean;
  /** Per-page list of image content hashes (order-stable). */
  imagesByPage: string[][];
}

async function loadPdfJs() {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const workerPath = path.join(
    process.cwd(),
    "node_modules",
    "pdfjs-dist",
    "legacy",
    "build",
    "pdf.worker.mjs",
  );
  pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(workerPath).href;
  return pdfjs;
}

async function extractStructure(data: Buffer): Promise<PdfStructure> {
  const pdfjs = await loadPdfJs();
  const pdf = await pdfjs.getDocument({
    data: new Uint8Array(data),
    useSystemFonts: true,
    disableFontFace: true,
  }).promise;

  const metaRaw = await pdf.getMetadata().catch(() => null);
  const info = (metaRaw?.info ?? {}) as Record<string, unknown>;
  const meta: Record<string, string> = {};
  for (const [k, v] of Object.entries(info)) {
    if (typeof v === "string") meta[k] = v;
  }

  const pageSizes: Array<{ width: number; height: number }> = [];
  const fontNames = new Set<string>();
  const annotations: Array<{ page: number; name: string; value: string }> = [];
  const formFields: Array<{ name: string; value: string }> = [];
  const formSeen = new Set<string>();
  const imagesByPage: string[][] = [];
  let hasJavaScript = false;

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const vp = page.getViewport({ scale: 1 });
    pageSizes.push({ width: vp.width, height: vp.height });

    const annots = await page.getAnnotations().catch(() => []);
    for (const a of annots as Array<Record<string, unknown>>) {
      const subtype = String(a.subtype ?? "");
      const fieldName = String(a.fieldName ?? a.id ?? subtype);
      const fieldValue = String(
        a.fieldValue ?? a.contents ?? a.alternativeText ?? "",
      );
      if (subtype === "Widget") {
        const key = `${fieldName}=${fieldValue}`;
        if (!formSeen.has(key)) {
          formSeen.add(key);
          formFields.push({ name: fieldName, value: fieldValue });
        }
      } else {
        annotations.push({
          page: i,
          name: `${subtype}:${fieldName}`,
          value: fieldValue.slice(0, 200),
        });
      }
      if (
        String(a.contents ?? "")
          .toLowerCase()
          .includes("javascript")
      ) {
        hasJavaScript = true;
      }
    }

    try {
      const common = await page.getTextContent();
      for (const item of common.items as Array<{ fontName?: string }>) {
        if (item.fontName) fontNames.add(item.fontName);
      }
    } catch {
      /* ignore */
    }

    const pageImages: string[] = [];
    try {
      const ops = await page.getOperatorList();
      const OPS = pdfjs.OPS as Record<string, number>;
      const paintOps = new Set(
        [
          OPS.paintImageXObject,
          OPS.paintInlineImageXObject,
          OPS.paintImageMaskXObject,
        ].filter((n) => typeof n === "number"),
      );
      for (let oi = 0; oi < ops.fnArray.length; oi++) {
        if (!paintOps.has(ops.fnArray[oi]!)) continue;
        const args = ops.argsArray[oi] as unknown[];
        const imgName = args?.[0];
        if (typeof imgName !== "string") continue;
        try {
          const img = await new Promise<{
            data?: Uint8Array | Uint8ClampedArray;
            width?: number;
            height?: number;
          } | null>((resolve) => {
            try {
              page.objs.get(imgName, (v: unknown) =>
                resolve(v as { data?: Uint8Array; width?: number; height?: number }),
              );
            } catch {
              resolve(null);
            }
          });
          if (img?.data) {
            const h = createHash("sha256")
              .update(Buffer.from(img.data))
              .update(String(img.width ?? 0))
              .update(String(img.height ?? 0))
              .digest("hex")
              .slice(0, 16);
            pageImages.push(h);
          } else {
            pageImages.push(`ref:${imgName}`);
          }
        } catch {
          pageImages.push(`ref:${imgName}`);
        }
      }
    } catch {
      /* ignore image extract failures per page */
    }
    imagesByPage.push(pageImages);
  }

  if (
    data.includes(Buffer.from("/JavaScript")) ||
    data.includes(Buffer.from("/JS"))
  ) {
    hasJavaScript = true;
  }

  return {
    pageCount: pdf.numPages,
    pageSizes,
    meta,
    annotations,
    formFields,
    fontNames: [...fontNames].sort(),
    hasJavaScript,
    imagesByPage,
  };
}

function compareFormat(
  a: PdfStructure,
  b: PdfStructure,
): AnalysisChange[] {
  const formatDiffs: AnalysisChange[] = [];

  const n = Math.min(a.pageSizes.length, b.pageSizes.length);
  for (let i = 0; i < n; i++) {
    const pa = a.pageSizes[i]!;
    const pb = b.pageSizes[i]!;
    if (
      Math.abs(pa.width - pb.width) > 0.5 ||
      Math.abs(pa.height - pb.height) > 0.5
    ) {
      formatDiffs.push({
        location: `page ${i + 1}`,
        description: `Page size ${pa.width}x${pa.height} → ${pb.width}x${pb.height}`,
        kind: "page-size",
      });
    }
  }

  const metaKeys = new Set([...Object.keys(a.meta), ...Object.keys(b.meta)]);
  for (const key of metaKeys) {
    if ((a.meta[key] ?? "") !== (b.meta[key] ?? "")) {
      formatDiffs.push({
        location: "metadata",
        description: `${key}: "${a.meta[key] ?? ""}" → "${b.meta[key] ?? ""}"`,
        kind: "metadata",
      });
    }
  }

  if (a.fontNames.join("|") !== b.fontNames.join("|")) {
    formatDiffs.push({
      location: "fonts",
      description: "Font list differs",
      kind: "fonts",
    });
  }

  return formatDiffs;
}

function compareEmbeddedImages(
  a: PdfStructure,
  b: PdfStructure,
): AnalysisChange[] {
  const changes: AnalysisChange[] = [];
  const pageCount = Math.max(a.imagesByPage.length, b.imagesByPage.length);
  for (let i = 0; i < pageCount; i++) {
    const oa = [...(a.imagesByPage[i] ?? [])].sort();
    const ub = [...(b.imagesByPage[i] ?? [])].sort();
    if (oa.join("|") === ub.join("|")) continue;

    const setA = new Map<string, number>();
    const setB = new Map<string, number>();
    for (const h of oa) setA.set(h, (setA.get(h) ?? 0) + 1);
    for (const h of ub) setB.set(h, (setB.get(h) ?? 0) + 1);

    let removed = 0;
    let added = 0;
    for (const [h, countA] of setA) {
      const countB = setB.get(h) ?? 0;
      if (countA > countB) removed += countA - countB;
    }
    for (const [h, countB] of setB) {
      const countA = setA.get(h) ?? 0;
      if (countB > countA) added += countB - countA;
    }

    const replaced = Math.min(removed, added);
    removed -= replaced;
    added -= replaced;
    for (let r = 0; r < replaced; r++) {
      changes.push({
        location: `page ${i + 1}`,
        description: `image replaced on page ${i + 1}`,
        kind: "embedded-image-replaced",
      });
    }
    for (let r = 0; r < removed; r++) {
      changes.push({
        location: `page ${i + 1}`,
        description: `image removed on page ${i + 1}`,
        kind: "embedded-image-removed",
      });
    }
    for (let r = 0; r < added; r++) {
      changes.push({
        location: `page ${i + 1}`,
        description: `image added on page ${i + 1}`,
        kind: "embedded-image-added",
      });
    }
  }
  return changes;
}

function compareAnnotations(
  a: PdfStructure,
  b: PdfStructure,
): AnalysisChange[] {
  const sa = JSON.stringify(a.annotations);
  const sb = JSON.stringify(b.annotations);
  if (sa === sb) return [];
  return [
    {
      location: "annotations",
      description: `Annotations differ (${a.annotations.length} → ${b.annotations.length})`,
      kind: "annotations",
    },
  ];
}

function compareFormFields(
  a: PdfStructure,
  b: PdfStructure,
): AnalysisChange[] {
  const mapA = new Map(a.formFields.map((f) => [f.name, f.value]));
  const mapB = new Map(b.formFields.map((f) => [f.name, f.value]));
  const changes: AnalysisChange[] = [];
  const names = new Set([...mapA.keys(), ...mapB.keys()]);
  for (const name of names) {
    if (!mapA.has(name)) {
      changes.push({
        location: "form",
        description: `Form field added: ${name}`,
        kind: "form-fields",
      });
    } else if (!mapB.has(name)) {
      changes.push({
        location: "form",
        description: `Form field removed: ${name}`,
        kind: "form-fields",
      });
    } else if (mapA.get(name) !== mapB.get(name)) {
      changes.push({
        location: "form",
        description: `Form field "${name}" value changed`,
        kind: "form-fields",
      });
    }
  }
  return changes;
}

async function thumbnailPng(
  rgba: Buffer,
  width: number,
  height: number,
  maxEdge = 360,
): Promise<{ base64: string; width: number; height: number }> {
  const { createCanvas } = await import("@napi-rs/canvas");
  const scale = Math.min(1, maxEdge / Math.max(width, height));
  const tw = Math.max(1, Math.round(width * scale));
  const th = Math.max(1, Math.round(height * scale));
  const src = createCanvas(width, height);
  const sctx = src.getContext("2d");
  const imgData = sctx.createImageData(width, height);
  imgData.data.set(rgba);
  sctx.putImageData(imgData, 0, 0);
  const dst = createCanvas(tw, th);
  const dctx = dst.getContext("2d");
  dctx.drawImage(src, 0, 0, tw, th);
  const png = dst.toBuffer("image/png");
  return { base64: png.toString("base64"), width: tw, height: th };
}

export class PdfAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return mime === "application/pdf" || ext === ".pdf";
  }

  async analyze(original: Buffer, uploaded: Buffer): Promise<AnalysisResult> {
    const originalSha = sha256Buffer(original);
    const uploadedSha = sha256Buffer(uploaded);
    if (originalSha === uploadedSha) {
      return deriveVerdict({
        originalSha256: originalSha,
        uploadedSha256: uploadedSha,
        checks: [],
        contentCheckNames: [...CONTENT_CHECK_NAMES],
        formatCheckNames: [...FORMAT_CHECK_NAMES],
        notChecked: [],
      });
    }

    const checks: CheckResult[] = [];
    const changes: AnalysisChange[] = [];
    const notChecked: string[] = [];
    let formatDifferences: AnalysisChange[] = [];
    let visualPages: VisualPageDiff[] = [];

    let structA: PdfStructure;
    let structB: PdfStructure;
    try {
      structA = await extractStructure(original);
      structB = await extractStructure(uploaded);
    } catch (err) {
      return unavailableResult(
        `PDF structure extraction failed: ${err instanceof Error ? err.message : String(err)}`,
        ["file-properties", "text", "visual", "embedded-images"],
      );
    }

    formatDifferences = compareFormat(structA, structB);

    // Page count is content
    if (structA.pageCount !== structB.pageCount) {
      changes.push({
        location: "document",
        description: `Page count ${structA.pageCount} → ${structB.pageCount}`,
        kind: "page-count",
      });
    }

    checks.push({
      name: "file-properties",
      status: formatDifferences.length === 0 ? "PASSED" : "FAILED",
      detail:
        formatDifferences.length === 0
          ? "Metadata and fonts match"
          : formatDifferences.map((d) => d.description).join("; "),
    });

    const annotDiffs = compareAnnotations(structA, structB);
    checks.push({
      name: "annotations",
      status: annotDiffs.length === 0 ? "PASSED" : "FAILED",
      detail:
        annotDiffs.length === 0
          ? "Annotations match"
          : annotDiffs.map((d) => d.description).join("; "),
    });
    changes.push(...annotDiffs);

    const formDiffs = compareFormFields(structA, structB);
    checks.push({
      name: "form-fields",
      status: formDiffs.length === 0 ? "PASSED" : "FAILED",
      detail:
        formDiffs.length === 0
          ? "Form fields match"
          : formDiffs.map((d) => d.description).join("; "),
    });
    changes.push(...formDiffs);

    if (structA.hasJavaScript !== structB.hasJavaScript) {
      changes.push({
        location: "javascript",
        description: `JavaScript present: ${structA.hasJavaScript} → ${structB.hasJavaScript}`,
        kind: "javascript",
      });
      // Treat JS presence change as annotation-like content
      const ann = checks.find((c) => c.name === "annotations");
      if (ann) {
        ann.status = "FAILED";
        ann.detail = `${ann.detail}; JavaScript flag changed`;
      }
    }

    const imageDiffs = compareEmbeddedImages(structA, structB);
    checks.push({
      name: "embedded-images",
      status: imageDiffs.length === 0 ? "PASSED" : "FAILED",
      detail:
        imageDiffs.length === 0
          ? "Embedded images match"
          : imageDiffs.map((d) => d.description).join("; "),
    });
    changes.push(...imageDiffs);

    // Text check
    let textFailed = false;
    let textPassedPages = 0;
    let scannedPages = 0;
    try {
      const [origPages, upPages] = await Promise.all([
        extractPdfPages(original),
        extractPdfPages(uploaded),
      ]);
      const pageCount = Math.max(origPages.pages.length, upPages.pages.length);
      for (let i = 0; i < pageCount; i++) {
        const ot = origPages.pages[i] ?? "";
        const ut = upPages.pages[i] ?? "";
        const sparse =
          ot.replace(/\s/g, "").length < analysisConfig.pdfScannedTextMinChars &&
          ut.replace(/\s/g, "").length < analysisConfig.pdfScannedTextMinChars;
        if (sparse) {
          scannedPages++;
          continue;
        }
        const diff = smartLineDiff(ot, ut);
        const substantive =
          (diff.counts?.added ?? 0) +
            (diff.counts?.removed ?? 0) +
            (diff.counts?.changed ?? 0) >
          0;
        if (substantive) {
          textFailed = true;
          changes.push({
            location: `page ${i + 1}`,
            description: "Text content differs",
            kind: "text",
          });
        } else {
          textPassedPages++;
        }
      }
      if (scannedPages > 0) {
        notChecked.push(`text (scanned pages: ${scannedPages})`);
      }
      checks.push({
        name: "text",
        status: textFailed
          ? "FAILED"
          : scannedPages > 0 && textPassedPages === 0
            ? "NOT_CHECKED"
            : "PASSED",
        detail: textFailed
          ? "Per-page text differs"
          : scannedPages > 0
            ? `Text sparse on ${scannedPages} page(s); rely on visual`
            : "Text identical",
      });
    } catch (err) {
      notChecked.push("text");
      checks.push({
        name: "text",
        status: "NOT_CHECKED",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    // Visual check with per-page changedPercent + bounding boxes
    let visualFailed = false;
    try {
      const { renderPdfPages } = await import("./render");
      const [rA, rB] = await Promise.all([
        renderPdfPages(original),
        renderPdfPages(uploaded),
      ]);
      if (rA.length !== rB.length) {
        visualFailed = true;
        changes.push({
          location: "document",
          description: `Rendered page count ${rA.length} → ${rB.length}`,
          kind: "visual",
        });
      }
      const pageResults: VisualPageDiff[] = [];
      for (let i = 0; i < Math.min(rA.length, rB.length); i++) {
        const a = rA[i]!;
        const b = rB[i]!;
        if (a.width !== b.width || a.height !== b.height) {
          visualFailed = true;
          pageResults.push({
            page: i + 1,
            changedPercent: 100,
            boxes: [
              {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                normalized: true,
                label: "Render size differs",
              },
            ],
          });
          changes.push({
            location: `page ${i + 1}`,
            description: "Render size differs",
            kind: "visual",
          });
          continue;
        }
        const diffMask = new Uint8Array(a.width * a.height * 4);
        const mismatched = pixelmatch(
          a.data,
          b.data,
          diffMask,
          a.width,
          a.height,
          { threshold: analysisConfig.pdfPixelmatchThreshold },
        );
        const total = a.width * a.height;
        const changedPercent = (mismatched / total) * 100;
        const boxes =
          changedPercent > analysisConfig.pdfVisualChangedPercentMax
            ? boundingBoxesFromDiffMask(diffMask, a.width, a.height)
            : [];

        // Label boxes that align with removed embedded images on this page
        const pageImageRemovals = imageDiffs.filter(
          (d) =>
            d.location === `page ${i + 1}` &&
            d.kind === "embedded-image-removed",
        );
        if (pageImageRemovals.length > 0 && boxes.length > 0) {
          boxes[0]!.label = "image removed";
        } else if (pageImageRemovals.length > 0 && boxes.length === 0) {
          boxes.push({
            x: 0.05,
            y: 0.05,
            width: 0.3,
            height: 0.2,
            normalized: true,
            label: "image removed",
          });
        }

        if (changedPercent > analysisConfig.pdfVisualChangedPercentMax) {
          visualFailed = true;
          changes.push({
            location: `page ${i + 1}`,
            description: `Visual differ ${changedPercent.toFixed(2)}% pixels`,
            kind: "visual",
          });
        }

        let uploadedThumbnailBase64: string | undefined;
        let originalThumbnailBase64: string | undefined;
        let thumbnailWidth: number | undefined;
        let thumbnailHeight: number | undefined;
        if (
          changedPercent > analysisConfig.pdfVisualChangedPercentMax ||
          pageImageRemovals.length > 0
        ) {
          try {
            const [upThumb, origThumb] = await Promise.all([
              thumbnailPng(b.data, b.width, b.height),
              thumbnailPng(a.data, a.width, a.height),
            ]);
            uploadedThumbnailBase64 = upThumb.base64;
            originalThumbnailBase64 = origThumb.base64;
            thumbnailWidth = upThumb.width;
            thumbnailHeight = upThumb.height;
          } catch {
            /* thumbnails optional */
          }
        }

        pageResults.push({
          page: i + 1,
          changedPercent,
          boxes,
          uploadedThumbnailBase64,
          originalThumbnailBase64,
          thumbnailWidth,
          thumbnailHeight,
        });
      }
      visualPages = pageResults;
      checks.push({
        name: "visual",
        status: visualFailed ? "FAILED" : "PASSED",
        detail: visualFailed
          ? "Pixel differences above tolerance"
          : "Visual appearance matches within tolerance",
      });
    } catch (err) {
      notChecked.push("visual");
      checks.push({
        name: "visual",
        status: "NOT_CHECKED",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    const contentCheckNames = [
      "text",
      "visual",
      "embedded-images",
      "annotations",
      "form-fields",
    ];
    const formatCheckNames = ["file-properties"];
    const requiredContentMissing =
      checks.some(
        (c) =>
          (c.name === "text" || c.name === "visual") &&
          c.status === "NOT_CHECKED",
      ) &&
      !checks.some(
        (c) =>
          (c.name === "text" || c.name === "visual") && c.status === "PASSED",
      );

    const result = deriveVerdict({
      originalSha256: originalSha,
      uploadedSha256: uploadedSha,
      checks,
      contentCheckNames,
      formatCheckNames,
      notChecked,
      requiredContentMissing,
    });

    const anyContentFailed = checks.some(
      (c) =>
        contentCheckNames.includes(c.name) && c.status === "FAILED",
    );
    const textOk = checks.find((c) => c.name === "text")?.status === "PASSED";
    const visualOk =
      checks.find((c) => c.name === "visual")?.status === "PASSED";

    if (!anyContentFailed && formatDifferences.length > 0) {
      return {
        verdict: Verdict.MODIFIED_FORMAT_ONLY,
        confidence: "HIGH",
        checks,
        changes: [],
        formatDifferences,
        visualPages,
        notChecked,
      };
    }

    if (anyContentFailed) {
      return {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks,
        changes,
        formatDifferences,
        visualPages,
        notChecked,
      };
    }

    if (textOk && visualOk && formatDifferences.length === 0) {
      return {
        ...result,
        changes,
        formatDifferences,
        visualPages,
      };
    }

    return {
      ...result,
      changes,
      formatDifferences,
      visualPages,
    };
  }
}
