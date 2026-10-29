import { createHash } from "crypto";
import { CHUNK_SIZE } from "../config";
import {
  detectBufferFormat,
  formatDisplayName,
  isPdfBuffer,
  type BufferFormat,
} from "../image/from-pdf";
import type { ByteRangeChange, DiffResult } from "./types";

const MAX_SANE_DIMENSION = 100_000;

export function computeChunkHashes(data: Buffer): string[] {
  const hashes: string[] = [];
  for (let i = 0; i < data.length; i += CHUNK_SIZE) {
    const block = data.subarray(i, Math.min(i + CHUNK_SIZE, data.length));
    hashes.push(createHash("sha256").update(block).digest("hex"));
  }
  return hashes;
}

function clampDim(n: number): number | undefined {
  if (!Number.isFinite(n) || n <= 0 || n > MAX_SANE_DIMENSION) return undefined;
  return n;
}

/** Detect image format of a buffer via magic bytes (PNG/JPEG/GIF/WebP). */
export function detectImageMagic(
  data: Buffer,
): "png" | "jpeg" | "gif" | "webp" | null {
  const f = detectBufferFormat(data);
  if (f === "png" || f === "jpeg" || f === "gif" || f === "webp") return f;
  return null;
}

function readPngDimensions(
  data: Buffer,
): { width: number; height: number } | undefined {
  if (data.length < 24) return undefined;
  const width = clampDim(data.readUInt32BE(16));
  const height = clampDim(data.readUInt32BE(20));
  if (width === undefined || height === undefined) return undefined;
  return { width, height };
}

function readJpegDimensions(
  data: Buffer,
): { width: number; height: number } | undefined {
  let offset = 2;
  while (offset + 9 < data.length) {
    if (data[offset] !== 0xff) break;
    const marker = data[offset + 1]!;
    if (marker === 0xd9 || marker === 0xda) break;
    const length = data.readUInt16BE(offset + 2);
    if (length < 2) break;
    // SOF0 / SOF2
    if (marker === 0xc0 || marker === 0xc2) {
      const height = clampDim(data.readUInt16BE(offset + 5));
      const width = clampDim(data.readUInt16BE(offset + 7));
      if (width === undefined || height === undefined) return undefined;
      return { width, height };
    }
    offset += 2 + length;
  }
  return undefined;
}

function readGifDimensions(
  data: Buffer,
): { width: number; height: number } | undefined {
  if (data.length < 10) return undefined;
  const width = clampDim(data.readUInt16LE(6));
  const height = clampDim(data.readUInt16LE(8));
  if (width === undefined || height === undefined) return undefined;
  return { width, height };
}

function readWebpDimensions(
  data: Buffer,
): { width: number; height: number } | undefined {
  if (data.length < 30) return undefined;
  const chunk = data.toString("ascii", 12, 16);
  if (chunk === "VP8X" && data.length >= 30) {
    const width = clampDim(1 + data.readUIntLE(24, 3));
    const height = clampDim(1 + data.readUIntLE(27, 3));
    if (width === undefined || height === undefined) return undefined;
    return { width, height };
  }
  if (chunk === "VP8 " && data.length >= 30) {
    // Lossy bitstream: 16-bit width/height at offset 26, low 14 bits
    const width = clampDim(data.readUInt16LE(26) & 0x3fff);
    const height = clampDim(data.readUInt16LE(28) & 0x3fff);
    if (width === undefined || height === undefined) return undefined;
    return { width, height };
  }
  if (chunk === "VP8L" && data.length >= 25) {
    const bits = data.readUInt32LE(21);
    const width = clampDim((bits & 0x3fff) + 1);
    const height = clampDim(((bits >> 14) & 0x3fff) + 1);
    if (width === undefined || height === undefined) return undefined;
    return { width, height };
  }
  return undefined;
}

/**
 * Peek image dimensions from magic-detected format only.
 * Never treats PDF/unknown buffers as PNG. Bounds each side to <= 100000.
 */
export function readImageDimensions(
  data: Buffer,
  _mimeType?: string,
): { width?: number; height?: number } | undefined {
  try {
    if (isPdfBuffer(data)) return undefined;
    const format = detectImageMagic(data);
    if (!format) return undefined;
    if (format === "png") return readPngDimensions(data);
    if (format === "jpeg") return readJpegDimensions(data);
    if (format === "gif") return readGifDimensions(data);
    if (format === "webp") return readWebpDimensions(data);
  } catch {
    return undefined;
  }
  return undefined;
}

function bufferFormatLabel(data: Buffer): string {
  const f: BufferFormat = detectBufferFormat(data);
  return formatDisplayName(f);
}

export function diffBinary(
  original: Buffer,
  uploaded: Buffer,
  storedChunkHashes?: string[],
): DiffResult {
  const origHashes = storedChunkHashes ?? computeChunkHashes(original);
  const upHashes = computeChunkHashes(uploaded);
  const max = Math.max(origHashes.length, upHashes.length);
  const changes: ByteRangeChange[] = [];

  for (let i = 0; i < max; i++) {
    if (origHashes[i] !== upHashes[i]) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(
        start + CHUNK_SIZE,
        Math.max(original.length, uploaded.length),
      );
      changes.push({ start, end, chunkIndex: i });
    }
  }

  const sizeDiff = uploaded.length - original.length;
  const sizeNote =
    sizeDiff === 0
      ? "same size"
      : sizeDiff > 0
        ? `${sizeDiff} bytes larger`
        : `${Math.abs(sizeDiff)} bytes smaller`;

  const origLabel = bufferFormatLabel(original);
  const upLabel = bufferFormatLabel(uploaded);
  const formatsDiffer = origLabel !== upLabel;
  const mostlyDifferent = max > 0 && changes.length / max > 0.5;

  if (formatsDiffer || mostlyDifferent) {
    return {
      type: "binary",
      summary: `The file format/encoding is completely different (${origLabel} → ${upLabel})`,
      changes: [],
      originalSize: original.length,
      uploadedSize: uploaded.length,
      note: "Binary content differs substantially; individual chunk ranges are omitted.",
    };
  }

  return {
    type: "binary",
    summary:
      changes.length === 0
        ? `Content differs but no chunk mismatch detected (${sizeNote})`
        : `${changes.length} chunk(s) differ (${sizeNote})`,
    changes,
    originalSize: original.length,
    uploadedSize: uploaded.length,
    note: "Binary content differs. Changed byte ranges are reported via 4 KB chunk hashes; a detailed semantic diff is not available for this file type.",
  };
}

export function diffImage(
  original: Buffer,
  uploaded: Buffer,
  mimeType: string,
  storedChunkHashes?: string[],
): DiffResult {
  const base = diffBinary(original, uploaded, storedChunkHashes);
  const originalMeta = readImageDimensions(original, mimeType);
  const uploadedMeta = readImageDimensions(uploaded, mimeType);

  // When formats differ heavily, keep the format summary (no fake dimensions).
  if (base.changes.length === 0 && /completely different/i.test(base.summary)) {
    return {
      ...base,
      type: "image",
      imageMeta: {
        original: originalMeta,
        uploaded: uploadedMeta,
      },
    };
  }

  return {
    ...base,
    type: "image",
    imageMeta: { original: originalMeta, uploaded: uploadedMeta },
    summary:
      originalMeta &&
      uploadedMeta &&
      (originalMeta.width !== uploadedMeta.width ||
        originalMeta.height !== uploadedMeta.height)
        ? `${base.summary}. Dimensions changed: ${originalMeta.width}x${originalMeta.height} → ${uploadedMeta.width}x${uploadedMeta.height}`
        : base.summary,
  };
}
