import sharp from "sharp";
import type { PixelBuffer } from "./pixels";

const CERTIFIABLE = new Set([
  "image/png",
  "image/jpeg",
  "image/jpg",
  "image/webp",
]);

const CERTIFIABLE_EXT = new Set([".png", ".jpg", ".jpeg", ".webp"]);

export function isCertifiableImage(
  mimeType: string,
  filename?: string,
): boolean {
  const mime = (mimeType || "").toLowerCase();
  if (CERTIFIABLE.has(mime)) return true;
  if (filename) {
    const ext = filename.includes(".")
      ? filename.slice(filename.lastIndexOf(".")).toLowerCase()
      : "";
    return CERTIFIABLE_EXT.has(ext);
  }
  return false;
}

/** Decode PNG/JPEG/WebP bytes to RGBA pixel buffer via sharp. */
export async function decodeImage(bytes: Buffer): Promise<PixelBuffer> {
  const { data, info } = await sharp(bytes)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  return {
    data: new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength),
    width: info.width,
    height: info.height,
  };
}

/** Encode pixels as lossless PNG (preserves watermark exactly). */
export async function encodePng(pixels: PixelBuffer): Promise<Buffer> {
  return sharp(Buffer.from(pixels.data), {
    raw: {
      width: pixels.width,
      height: pixels.height,
      channels: 4,
    },
  })
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toBuffer();
}

/** Re-encode as JPEG at a given quality (for robustness tests). */
export async function encodeJpeg(
  pixels: PixelBuffer,
  quality = 85,
): Promise<Buffer> {
  return sharp(Buffer.from(pixels.data), {
    raw: {
      width: pixels.width,
      height: pixels.height,
      channels: 4,
    },
  })
    .jpeg({ quality, chromaSubsampling: "4:2:0" })
    .toBuffer();
}

/** Resize to exact dimensions (used when aspect matches but size differs). */
export async function resizePixels(
  pixels: PixelBuffer,
  width: number,
  height: number,
): Promise<PixelBuffer> {
  const buf = await sharp(Buffer.from(pixels.data), {
    raw: {
      width: pixels.width,
      height: pixels.height,
      channels: 4,
    },
  })
    .resize(width, height, { fit: "fill" })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  return {
    data: new Uint8ClampedArray(
      buf.data.buffer,
      buf.data.byteOffset,
      buf.data.byteLength,
    ),
    width: buf.info.width,
    height: buf.info.height,
  };
}

export function aspectRatio(width: number, height: number): number {
  if (height === 0) return 0;
  return width / height;
}

/** True if aspect ratios differ beyond a small relative epsilon. */
export function aspectDiffers(
  aW: number,
  aH: number,
  bW: number,
  bH: number,
  epsilon = 0.01,
): boolean {
  const ar = aspectRatio(aW, aH);
  const br = aspectRatio(bW, bH);
  if (ar === 0 || br === 0) return true;
  return Math.abs(ar - br) / Math.max(ar, br) > epsilon;
}
