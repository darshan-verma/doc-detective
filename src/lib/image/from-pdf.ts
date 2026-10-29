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
  if (
    data.length >= 2 &&
    data[0] === 0x42 &&
    data[1] === 0x4d
  ) {
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
  return format === "png" || format === "jpeg" || format === "webp" || format === "gif";
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
  // ImageKind: GRAYSCALE_1BPP=1, RGB_24BPP=2, RGBA_32BPP=3
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
    // 1bpp packed — expand to gray
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

async function extractLargestEmbeddedImage(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  pdfjs: any,
): Promise<PixelBuffer | null> {
  const ops = await page.getOperatorList();
  const OPS = pdfjs.OPS as Record<string, number>;
  const paintOps = new Set(
    [
      OPS.paintImageXObject,
      OPS.paintInlineImageXObject,
      OPS.paintImageMaskXObject,
    ].filter((n) => typeof n === "number"),
  );

  let best: PixelBuffer | null = null;
  let bestArea = 0;

  for (let oi = 0; oi < ops.fnArray.length; oi++) {
    if (!paintOps.has(ops.fnArray[oi]!)) continue;
    const args = ops.argsArray[oi] as unknown[];
    const imgName = args?.[0];
    if (typeof imgName !== "string") continue;
    try {
      const img = await new Promise<PdfJsImage | null>((resolve) => {
        try {
          page.objs.get(imgName, (v: unknown) => resolve(v as PdfJsImage));
        } catch {
          resolve(null);
        }
      });
      if (!img) continue;
      const pixels = rgbaFromPdfImage(img);
      if (!pixels) continue;
      const area = pixels.width * pixels.height;
      if (area > bestArea) {
        bestArea = area;
        best = pixels;
      }
    } catch {
      /* skip unreadable XObject */
    }
  }

  return best;
}

async function renderPageToMatchSize(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  page: any,
  targetWidth: number,
  targetHeight: number,
): Promise<PixelBuffer> {
  const { createCanvas } = await import("@napi-rs/canvas");
  const base = page.getViewport({ scale: 1 });
  const scaleX = targetWidth / base.width;
  const scaleY = targetHeight / base.height;
  // Prefer exact match on width; fall back to height if needed.
  const scale =
    Math.abs(scaleX * base.height - targetHeight) <
    Math.abs(scaleY * base.width - targetWidth)
      ? scaleX
      : scaleY;

  const viewport = page.getViewport({ scale });
  const canvas = createCanvas(
    Math.ceil(viewport.width),
    Math.ceil(viewport.height),
  );
  const ctx = canvas.getContext("2d");
  await page.render({
    canvasContext: ctx as unknown as CanvasRenderingContext2D,
    canvas: canvas as unknown as HTMLCanvasElement,
    viewport,
  }).promise;
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return {
    data: new Uint8ClampedArray(imageData.data),
    width: canvas.width,
    height: canvas.height,
  };
}

export type PdfImageExtractResult =
  | {
      ok: true;
      pixels: PixelBuffer;
      source: "embedded" | "rendered";
      pageCount: number;
    }
  | {
      ok: false;
      reason: "multi-page" | "no-usable-image";
      pageCount: number;
    };

/**
 * Extract pixels from a PDF that wraps a certified image (e.g. Preview
 * "Export as PDF"). Prefers the largest embedded image XObject on a single
 * page; otherwise renders the page to match the certified dimensions.
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
  const embedded = await extractLargestEmbeddedImage(page, pdfjs);
  if (embedded) {
    return { ok: true, pixels: embedded, source: "embedded", pageCount };
  }

  const tw = targetSize?.width ?? 0;
  const th = targetSize?.height ?? 0;
  if (tw >= 1 && th >= 1) {
    try {
      const rendered = await renderPageToMatchSize(page, tw, th);
      return { ok: true, pixels: rendered, source: "rendered", pageCount };
    } catch {
      return { ok: false, reason: "no-usable-image", pageCount };
    }
  }

  return { ok: false, reason: "no-usable-image", pageCount };
}

export const PDF_IMAGE_UNAVAILABLE_MESSAGE =
  "This PDF does not contain a single image matching the certified file.";
