import path from "path";
import { pathToFileURL } from "url";
import type { PixelBuffer } from "./pixels";

const PDF_MAGIC = Buffer.from("%PDF");

export type BufferFormat =
  | "png"
  | "jpeg"
  | "gif"
  | "webp"
  | "pdf"
  | "bmp"
  | "tiff"
  | "unknown";

export function isPdfBuffer(data: Buffer): boolean {
  return data.length >= 4 && data.subarray(0, 4).equals(PDF_MAGIC);
}

/** Detect container format from magic bytes (not filename / Content-Type). */
export function detectBufferFormat(data: Buffer): BufferFormat {
  if (isPdfBuffer(data)) return "pdf";
  if (
    data.length >= 8 &&
    data[0] === 0x89 &&
    data[1] === 0x50 &&
    data[2] === 0x4e &&
    data[3] === 0x47 &&
    data[4] === 0x0d &&
    data[5] === 0x0a &&
    data[6] === 0x1a &&
    data[7] === 0x0a
  ) {
    return "png";
  }
  if (data.length >= 2 && data[0] === 0xff && data[1] === 0xd8) return "jpeg";
  if (
    data.length >= 6 &&
    data[0] === 0x47 &&
    data[1] === 0x49 &&
    data[2] === 0x46 &&
    data[3] === 0x38 &&
    (data[4] === 0x37 || data[4] === 0x39) &&
    data[5] === 0x61
  ) {
    return "gif";
  }
  if (
    data.length >= 12 &&
    data.toString("ascii", 0, 4) === "RIFF" &&
    data.toString("ascii", 8, 12) === "WEBP"
  ) {
    return "webp";
  }
  if (data.length >= 2 && data[0] === 0x42 && data[1] === 0x4d) {
    return "bmp";
  }
  if (
    data.length >= 4 &&
    ((data[0] === 0x49 &&
      data[1] === 0x49 &&
      data[2] === 0x2a &&
      data[3] === 0x00) ||
      (data[0] === 0x4d &&
        data[1] === 0x4d &&
        data[2] === 0x00 &&
        data[3] === 0x2a))
  ) {
    return "tiff";
  }
  return "unknown";
}

/** Formats we can feed to sharp for image-certificate verification. */
export function isSharpDecodableImageFormat(format: BufferFormat): boolean {
  return (
    format === "png" ||
    format === "jpeg" ||
    format === "webp" ||
    format === "gif"
  );
}

export function formatDisplayName(format: BufferFormat): string {
  switch (format) {
    case "png":
      return "PNG";
    case "jpeg":
      return "JPEG";
    case "gif":
      return "GIF";
    case "webp":
      return "WebP";
    case "pdf":
      return "PDF";
    case "bmp":
      return "BMP";
    case "tiff":
      return "TIFF";
    default:
      return "unknown";
  }
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

type Matrix = [number, number, number, number, number, number];

const IDENTITY: Matrix = [1, 0, 0, 1, 0, 0];

function mulMatrix(m1: Matrix, m2: Matrix): Matrix {
  const [a1, b1, c1, d1, e1, f1] = m1;
  const [a2, b2, c2, d2, e2, f2] = m2;
  return [
    a1 * a2 + b1 * c2,
    a1 * b2 + b1 * d2,
    c1 * a2 + d1 * c2,
    c1 * b2 + d1 * d2,
    e1 * a2 + f1 * c2 + e2,
    e1 * b2 + f1 * d2 + f2,
  ];
}

function applyMatrix(m: Matrix, x: number, y: number): [number, number] {
  return [m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]];
}

export interface PageRect {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

function unitSquareBBox(m: Matrix): PageRect {
  const corners: Array<[number, number]> = [
    [0, 0],
    [1, 0],
    [0, 1],
    [1, 1],
  ].map(([x, y]) => applyMatrix(m, x, y));
  const xs = corners.map((c) => c[0]!);
  const ys = corners.map((c) => c[1]!);
  return {
    x0: Math.min(...xs),
    y0: Math.min(...ys),
    x1: Math.max(...xs),
    y1: Math.max(...ys),
  };
}

function transformLocalBBox(m: Matrix, local: PageRect): PageRect {
  const corners: Array<[number, number]> = [
    [local.x0, local.y0],
    [local.x1, local.y0],
    [local.x0, local.y1],
    [local.x1, local.y1],
  ].map(([x, y]) => applyMatrix(m, x, y));
  const xs = corners.map((c) => c[0]!);
  const ys = corners.map((c) => c[1]!);
  return {
    x0: Math.min(...xs),
    y0: Math.min(...ys),
    x1: Math.max(...xs),
    y1: Math.max(...ys),
  };
}

export function rectsOverlap(a: PageRect, b: PageRect, eps = 0.5): boolean {
  return !(
    a.x1 <= b.x0 + eps ||
    a.x0 >= b.x1 - eps ||
    a.y1 <= b.y0 + eps ||
    a.y0 >= b.y1 - eps
  );
}

function rectArea(r: PageRect): number {
  return Math.max(0, r.x1 - r.x0) * Math.max(0, r.y1 - r.y0);
}

type PdfJsImage = {
  data?: Uint8Array | Uint8ClampedArray;
  width?: number;
  height?: number;
  kind?: number;
};

function rgbaFromPdfImage(img: PdfJsImage): PixelBuffer | null {
  const width = img.width ?? 0;
  const height = img.height ?? 0;
  const src = img.data;
  if (!src || width < 1 || height < 1) return null;

  const rgba = new Uint8ClampedArray(width * height * 4);
  const kind = img.kind ?? 0;
  if (kind === 3 || src.length === width * height * 4) {
    rgba.set(src.subarray(0, width * height * 4));
  } else if (kind === 2 || src.length === width * height * 3) {
    for (let i = 0, j = 0; i < width * height; i++, j += 3) {
      const o = i * 4;
      rgba[o] = src[j]!;
      rgba[o + 1] = src[j + 1]!;
      rgba[o + 2] = src[j + 2]!;
      rgba[o + 3] = 255;
    }
  } else if (kind === 1 || src.length >= Math.ceil((width * height) / 8)) {
    let bit = 0;
    let byteIndex = 0;
    for (let i = 0; i < width * height; i++) {
      const byte = src[byteIndex] ?? 0;
      const bitVal = (byte >> (7 - bit)) & 1;
      const v = bitVal ? 255 : 0;
      const o = i * 4;
      rgba[o] = v;
      rgba[o + 1] = v;
      rgba[o + 2] = v;
      rgba[o + 3] = 255;
      bit++;
      if (bit === 8) {
        bit = 0;
        byteIndex++;
      }
    }
  } else if (src.length === width * height) {
    for (let i = 0; i < width * height; i++) {
      const v = src[i]!;
      const o = i * 4;
      rgba[o] = v;
      rgba[o + 1] = v;
      rgba[o + 2] = v;
      rgba[o + 3] = 255;
    }
  } else {
    return null;
  }

  return { data: rgba, width, height };
}

export type PdfOverlayKind =
  | "text"
  | "path"
  | "xobject"
  | "annotation"
  | "form-widget";

export interface PdfOverlayElement {
  kind: PdfOverlayKind;
  detail: string;
  overlapsImage: boolean;
  rect?: PageRect;
}

interface ImageDraw {
  name: string;
  bbox: PageRect;
  pixels: PixelBuffer | null;
}

interface PageStructure {
  imageDraws: ImageDraw[];
  overlays: PdfOverlayElement[];
}

function numbersFromUnknown(value: unknown): number[] | null {
  if (Array.isArray(value)) {
    return value.map((v) => Number(v));
  }
  if (ArrayBuffer.isView(value)) {
    return Array.from(value as unknown as ArrayLike<number>).map((v) =>
      Number(v),
    );
  }
  return null;
}

function asMatrix(args: unknown): Matrix | null {
  if (!args) return null;
  const arr = numbersFromUnknown(args);
  if (!arr || arr.length < 6) return null;
  return [
    Number(arr[0]),
    Number(arr[1]),
    Number(arr[2]),
    Number(arr[3]),
    Number(arr[4]),
    Number(arr[5]),
  ];
}

function localBBoxFromArgs(args: unknown[]): PageRect | null {
  const maybe = args[2] ?? args[1];
  if (!maybe) return null;
  const arr = numbersFromUnknown(maybe);
  if (!arr || arr.length < 4) return null;
  const x0 = Number(arr[0]);
  const y0 = Number(arr[1]);
  const x1 = Number(arr[2]);
  const y1 = Number(arr[3]);
  if (![x0, y0, x1, y1].every((n) => Number.isFinite(n))) return null;
  return {
    x0: Math.min(x0, x1),
    y0: Math.min(y0, y1),
    x1: Math.max(x0, x1),
    y1: Math.max(y0, y1),
  };
}

async function analyzePageStructure(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  pdfjs: any,
): Promise<PageStructure> {
  const ops = await page.getOperatorList({
    annotationMode: pdfjs.AnnotationMode.ENABLE_STORAGE,
  });
  const OPS = pdfjs.OPS as Record<string, number>;

  const imageDraws: ImageDraw[] = [];
  const overlays: PdfOverlayElement[] = [];

  let ctm: Matrix = [...IDENTITY];
  const stack: Matrix[] = [];
  let textMatrix: Matrix = [...IDENTITY];
  let fontSize = 12;
  let inText = false;

  const paintImageOps = new Set(
    [
      OPS.paintImageXObject,
      OPS.paintInlineImageXObject,
      OPS.paintImageMaskXObject,
    ].filter((n) => typeof n === "number"),
  );

  for (let oi = 0; oi < ops.fnArray.length; oi++) {
    const fn = ops.fnArray[oi]!;
    const args = (ops.argsArray[oi] ?? []) as unknown[];

    if (fn === OPS.save) {
      stack.push([...ctm]);
      continue;
    }
    if (fn === OPS.restore) {
      ctm = stack.pop() ?? [...IDENTITY];
      continue;
    }
    if (fn === OPS.transform) {
      const m = asMatrix(args);
      if (m) ctm = mulMatrix(m, ctm);
      continue;
    }
    if (fn === OPS.beginText) {
      inText = true;
      textMatrix = [...IDENTITY];
      continue;
    }
    if (fn === OPS.endText) {
      inText = false;
      continue;
    }
    if (fn === OPS.setFont) {
      const size = Number(args[1]);
      if (Number.isFinite(size) && size > 0) fontSize = size;
      continue;
    }
    if (fn === OPS.setTextMatrix) {
      const m = asMatrix(args[0] ?? args);
      if (m) textMatrix = m;
      continue;
    }
    if (fn === OPS.showText || fn === OPS.showSpacedText) {
      const glyphs = args[0];
      let widthEm = 0;
      if (Array.isArray(glyphs)) {
        for (const g of glyphs) {
          if (g && typeof g === "object" && "width" in g) {
            widthEm += Number((g as { width: number }).width) || 0;
          } else if (typeof g === "number" && g < 0) {
            widthEm += -g;
          }
        }
      }
      const w = (widthEm / 1000) * fontSize;
      const h = fontSize;
      // Text space → combine text matrix with CTM for page space.
      const combined = mulMatrix(textMatrix, ctm);
      const origin = applyMatrix(combined, 0, 0);
      const end = applyMatrix(combined, w || fontSize, 0);
      const up = applyMatrix(combined, 0, h);
      const xs = [origin[0], end[0], up[0]];
      const ys = [origin[1], end[1], up[1]];
      const rect: PageRect = {
        x0: Math.min(...xs),
        y0: Math.min(...ys) - h,
        x1: Math.max(...xs),
        y1: Math.max(...ys) + h * 0.25,
      };
      overlays.push({
        kind: "text",
        detail: inText ? "Text drawn on page" : "Text operator",
        overlapsImage: false,
        rect,
      });
      continue;
    }

    if (
      fn === OPS.fill ||
      fn === OPS.eoFill ||
      fn === OPS.stroke ||
      fn === OPS.closeStroke ||
      fn === OPS.fillStroke ||
      fn === OPS.eoFillStroke ||
      fn === OPS.closeFillStroke ||
      fn === OPS.closeEOFillStroke ||
      fn === OPS.constructPath
    ) {
      let rect: PageRect | undefined;
      if (fn === OPS.constructPath) {
        const local = localBBoxFromArgs(args);
        if (local) rect = transformLocalBBox(ctm, local);
      } else if (fn === OPS.rectangle) {
        const x = Number(args[0]);
        const y = Number(args[1]);
        const w = Number(args[2]);
        const h = Number(args[3]);
        if ([x, y, w, h].every((n) => Number.isFinite(n))) {
          rect = transformLocalBBox(ctm, {
            x0: x,
            y0: y,
            x1: x + w,
            y1: y + h,
          });
        }
      }
      overlays.push({
        kind: "path",
        detail: "Path fill/stroke on page",
        overlapsImage: false,
        rect,
      });
      continue;
    }

    if (paintImageOps.has(fn)) {
      const imgName = typeof args[0] === "string" ? args[0] : `inline-${oi}`;
      const bbox = unitSquareBBox(ctm);
      let pixels: PixelBuffer | null = null;
      if (typeof args[0] === "string") {
        try {
          const img = await new Promise<PdfJsImage | null>((resolve) => {
            try {
              page.objs.get(args[0] as string, (v: unknown) =>
                resolve(v as PdfJsImage),
              );
            } catch {
              resolve(null);
            }
          });
          if (img) pixels = rgbaFromPdfImage(img);
        } catch {
          pixels = null;
        }
      }
      imageDraws.push({ name: imgName, bbox, pixels });
      continue;
    }

    if (fn === OPS.paintXObject) {
      const name = typeof args[0] === "string" ? args[0] : "XObject";
      overlays.push({
        kind: "xobject",
        detail: `Additional XObject "${name}"`,
        overlapsImage: false,
        rect: unitSquareBBox(ctm),
      });
    }
  }

  // Annotations (except Link)
  try {
    const annots = await page.getAnnotations({ intent: "display" });
    for (const a of annots as Array<Record<string, unknown>>) {
      const subtype = String(a.subtype ?? "");
      if (subtype === "Link") continue;
      const r = a.rect as number[] | undefined;
      let rect: PageRect | undefined;
      if (r && r.length >= 4) {
        rect = {
          x0: Math.min(r[0]!, r[2]!),
          y0: Math.min(r[1]!, r[3]!),
          x1: Math.max(r[0]!, r[2]!),
          y1: Math.max(r[1]!, r[3]!),
        };
      }
      const kind: PdfOverlayKind =
        subtype === "Widget" ? "form-widget" : "annotation";
      overlays.push({
        kind,
        detail:
          subtype === "Widget"
            ? `Form widget${a.fieldName ? ` "${String(a.fieldName)}"` : ""}`
            : `${subtype || "Annotation"} annotation`,
        overlapsImage: false,
        rect,
      });
    }
  } catch {
    /* ignore annotation read failures */
  }

  return { imageDraws, overlays };
}

async function renderImageArea(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  pdfjs: any,
  imageBBox: PageRect,
  targetWidth: number,
  targetHeight: number,
): Promise<PixelBuffer> {
  const { createCanvas } = await import("@napi-rs/canvas");
  const sharp = (await import("sharp")).default;

  const bw = Math.max(imageBBox.x1 - imageBBox.x0, 1e-6);
  const bh = Math.max(imageBBox.y1 - imageBBox.y0, 1e-6);
  // Render so the image area has at least ~2× target pixels (quality headroom).
  const scale = Math.max(
    (targetWidth * 2) / bw,
    (targetHeight * 2) / bh,
    1,
  );

  const viewport = page.getViewport({ scale });
  const canvas = createCanvas(
    Math.ceil(viewport.width),
    Math.ceil(viewport.height),
  );
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  await page.render({
    canvasContext: ctx as unknown as CanvasRenderingContext2D,
    canvas: canvas as unknown as HTMLCanvasElement,
    viewport,
    annotationMode: pdfjs.AnnotationMode.ENABLE_STORAGE,
  }).promise;

  const corners = [
    [imageBBox.x0, imageBBox.y0],
    [imageBBox.x1, imageBBox.y0],
    [imageBBox.x0, imageBBox.y1],
    [imageBBox.x1, imageBBox.y1],
  ].map(([x, y]) => viewport.convertToViewportPoint(x, y) as [number, number]);
  const xs = corners.map((c) => c[0]!);
  const ys = corners.map((c) => c[1]!);
  const left = Math.max(0, Math.floor(Math.min(...xs)));
  const top = Math.max(0, Math.floor(Math.min(...ys)));
  const right = Math.min(canvas.width, Math.ceil(Math.max(...xs)));
  const bottom = Math.min(canvas.height, Math.ceil(Math.max(...ys)));
  const cropW = Math.max(1, right - left);
  const cropH = Math.max(1, bottom - top);

  const imageData = ctx.getImageData(left, top, cropW, cropH);
  const resized = await sharp(Buffer.from(imageData.data), {
    raw: { width: cropW, height: cropH, channels: 4 },
  })
    .resize(targetWidth, targetHeight, { fit: "fill" })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  return {
    data: new Uint8ClampedArray(
      resized.data.buffer,
      resized.data.byteOffset,
      resized.data.byteLength,
    ),
    width: resized.info.width,
    height: resized.info.height,
  };
}

export type PdfImageExtractResult =
  | {
      ok: true;
      /** Rendered (annotations on), cropped to image bbox, resampled to target. */
      pixels: PixelBuffer;
      /** Raw embedded image XObject pixels, if available (diagnostic only). */
      embeddedPixels: PixelBuffer | null;
      pageCount: number;
      imageDrawCount: number;
      imageBBox: PageRect;
      overlays: PdfOverlayElement[];
      /** True when any non-image content overlaps the placed image area. */
      hasOverlappingContent: boolean;
      /**
       * One page, exactly one image draw, no overlapping content/annotations.
       * Required for MODIFIED_REENCODED.
       */
      cleanSingleImage: boolean;
    }
  | {
      ok: false;
      reason: "multi-page" | "no-usable-image";
      pageCount: number;
    };

/**
 * Extract what a viewer sees for an image-certificate PDF upload:
 * render the single page with annotations, crop to the placed image's
 * transform bbox, resample to the certified dimensions. Embedded XObject
 * bytes are returned only for overlay diagnostics.
 */
export async function extractImagePixelsFromPdf(
  pdfBytes: Buffer,
  targetSize?: { width?: number | null; height?: number | null },
): Promise<PdfImageExtractResult> {
  const pdfjs = await loadPdfJs();
  const pdf = await pdfjs.getDocument({
    data: new Uint8Array(pdfBytes),
    useSystemFonts: true,
    disableFontFace: true,
  }).promise;

  const pageCount = pdf.numPages;
  if (pageCount !== 1) {
    return { ok: false, reason: "multi-page", pageCount };
  }

  const page = await pdf.getPage(1);
  const structure = await analyzePageStructure(page, pdfjs);
  if (structure.imageDraws.length === 0) {
    return { ok: false, reason: "no-usable-image", pageCount };
  }

  // Prefer the largest placed image (by page-area) as the certified subject.
  let best = structure.imageDraws[0]!;
  let bestArea = rectArea(best.bbox);
  for (const draw of structure.imageDraws.slice(1)) {
    const area = rectArea(draw.bbox);
    if (area > bestArea) {
      best = draw;
      bestArea = area;
    }
  }

  const imageBBox = best.bbox;
  const overlays = structure.overlays.map((o) => {
    const overlapsImage = o.rect
      ? rectsOverlap(o.rect, imageBBox)
      : // Unknown bounds — treat as overlapping (fail closed for security).
        true;
    return { ...o, overlapsImage };
  });
  const hasOverlappingContent = overlays.some((o) => o.overlapsImage);
  const cleanSingleImage =
    structure.imageDraws.length === 1 && !hasOverlappingContent;

  const tw = targetSize?.width ?? best.pixels?.width ?? 0;
  const th = targetSize?.height ?? best.pixels?.height ?? 0;
  if (tw < 1 || th < 1) {
    return { ok: false, reason: "no-usable-image", pageCount };
  }

  let pixels: PixelBuffer;
  try {
    pixels = await renderImageArea(page, pdfjs, imageBBox, tw, th);
  } catch (err) {
    console.error("[extractImagePixelsFromPdf] render failed", err);
    return { ok: false, reason: "no-usable-image", pageCount };
  }

  return {
    ok: true,
    pixels,
    embeddedPixels: best.pixels,
    pageCount,
    imageDrawCount: structure.imageDraws.length,
    imageBBox,
    overlays,
    hasOverlappingContent,
    cleanSingleImage,
  };
}

export const PDF_IMAGE_UNAVAILABLE_MESSAGE =
  "This PDF does not contain a single image matching the certified file.";

export const PDF_OVERLAY_TAMPER_REASON =
  "Content was drawn over the image inside the PDF";
