import { createHash } from "crypto";
import { CHUNK_SIZE } from "../config";
import type { ByteRangeChange, DiffResult } from "./types";

export function computeChunkHashes(data: Buffer): string[] {
  const hashes: string[] = [];
  for (let i = 0; i < data.length; i += CHUNK_SIZE) {
    const block = data.subarray(i, Math.min(i + CHUNK_SIZE, data.length));
    hashes.push(createHash("sha256").update(block).digest("hex"));
  }
  return hashes;
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

/** Minimal PNG/JPEG dimension peek without heavy deps. */
export function readImageDimensions(
  data: Buffer,
  mimeType: string,
): { width?: number; height?: number } | undefined {
  try {
    if (mimeType === "image/png" || data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
      if (data.length < 24) return undefined;
      return {
        width: data.readUInt32BE(16),
        height: data.readUInt32BE(20),
      };
    }
    if (
      mimeType === "image/jpeg" ||
      mimeType === "image/jpg" ||
      (data[0] === 0xff && data[1] === 0xd8)
    ) {
      let offset = 2;
      while (offset < data.length) {
        if (data[offset] !== 0xff) break;
        const marker = data[offset + 1]!;
        const length = data.readUInt16BE(offset + 2);
        // SOF0 / SOF2
        if (marker === 0xc0 || marker === 0xc2) {
          return {
            height: data.readUInt16BE(offset + 5),
            width: data.readUInt16BE(offset + 7),
          };
        }
        offset += 2 + length;
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
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
