import { createHash, createHmac } from "crypto";
import { dct2d, idct2d } from "./dct";
import type { PixelBuffer } from "./pixels";
import { clonePixels } from "./pixels";

export const WATERMARK_VERSION = 1;

/** Mid-frequency coefficient indices (u,v) in 8×8 DCT. */
const MID_U = 3;
const MID_V = 4;
const BLOCK = 8;
/** Fixed payload: 8-char certId (64 bits) + 8-bit checksum = 72 bits. */
export const CERT_ID_BYTES = 8;
export const PAYLOAD_BITS = CERT_ID_BYTES * 8 + 8;

export interface EmbedOptions {
  key: string;
  step?: number;
}

export interface ExtractResult {
  payload: string;
  payloadBits: number[];
  confidence: number;
}

function rgbToYCbCr(r: number, g: number, b: number) {
  const Y = 0.299 * r + 0.587 * g + 0.114 * b;
  const Cb = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b;
  const Cr = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b;
  return { Y, Cb, Cr };
}

function yCbCrToRgb(Y: number, Cb: number, Cr: number) {
  const r = Y + 1.402 * (Cr - 128);
  const g = Y - 0.344136 * (Cb - 128) - 0.714136 * (Cr - 128);
  const b = Y + 1.772 * (Cb - 128);
  return {
    r: Math.max(0, Math.min(255, Math.round(r))),
    g: Math.max(0, Math.min(255, Math.round(g))),
    b: Math.max(0, Math.min(255, Math.round(b))),
  };
}

function checksumByte(bytes: Uint8Array): number {
  let x = 0;
  for (const b of bytes) x ^= b;
  return x & 0xff;
}

/** Encode certId into fixed-length bit array + checksum. */
export function encodePayload(certId: string): number[] {
  const padded = certId.toUpperCase().padEnd(CERT_ID_BYTES, "\0").slice(0, CERT_ID_BYTES);
  const bytes = new Uint8Array(CERT_ID_BYTES + 1);
  for (let i = 0; i < CERT_ID_BYTES; i++) {
    bytes[i] = padded.charCodeAt(i) & 0xff;
  }
  bytes[CERT_ID_BYTES] = checksumByte(bytes.subarray(0, CERT_ID_BYTES));
  const bits: number[] = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((b >> i) & 1);
    }
  }
  return bits;
}

export function decodePayload(bits: number[]): string | null {
  if (bits.length < PAYLOAD_BITS) return null;
  const bytes = new Uint8Array(CERT_ID_BYTES + 1);
  for (let i = 0; i < CERT_ID_BYTES + 1; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) {
      b = (b << 1) | (bits[i * 8 + j]! & 1);
    }
    bytes[i] = b;
  }
  if (bytes[CERT_ID_BYTES] !== checksumByte(bytes.subarray(0, CERT_ID_BYTES))) {
    return null;
  }
  let s = "";
  for (let i = 0; i < CERT_ID_BYTES; i++) {
    const c = bytes[i]!;
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s || null;
}

/** Keyed PRNG → shuffled list of block indices. */
function shuffledBlockOrder(
  blockCount: number,
  key: string,
): number[] {
  const indices = Array.from({ length: blockCount }, (_, i) => i);
  let counter = 0;
  const nextU32 = (): number => {
    const c = counter++;
    const h = createHmac("sha256", key)
      .update(
        Buffer.from([
          c & 0xff,
          (c >> 8) & 0xff,
          (c >> 16) & 0xff,
          (c >> 24) & 0xff,
        ]),
      )
      .digest();
    return h.readUInt32BE(0);
  };
  for (let i = indices.length - 1; i > 0; i--) {
    const j = nextU32() % (i + 1);
    const tmp = indices[i]!;
    indices[i] = indices[j]!;
    indices[j] = tmp;
  }
  return indices;
}

function qimEmbed(coeff: number, bit: number, step: number): number {
  const q = Math.round(coeff / step);
  const wantEven = bit === 0;
  const isEven = ((q % 2) + 2) % 2 === 0;
  let qAdj = q;
  if (isEven !== wantEven) {
    const down = q - 1;
    const up = q + 1;
    qAdj =
      Math.abs(coeff - down * step) <= Math.abs(coeff - up * step) ? down : up;
  }
  return qAdj * step;
}

function qimExtract(coeff: number, step: number): number {
  const q = Math.round(coeff / step);
  return ((q % 2) + 2) % 2;
}

function blockCount(width: number, height: number): {
  cols: number;
  rows: number;
  total: number;
} {
  const cols = Math.floor(width / BLOCK);
  const rows = Math.floor(height / BLOCK);
  return { cols, rows, total: cols * rows };
}

function readYBlock(
  Y: Float64Array,
  width: number,
  bx: number,
  by: number,
): Float64Array {
  const block = new Float64Array(BLOCK * BLOCK);
  for (let y = 0; y < BLOCK; y++) {
    for (let x = 0; x < BLOCK; x++) {
      block[y * BLOCK + x] = Y[(by * BLOCK + y) * width + (bx * BLOCK + x)]!;
    }
  }
  return block;
}

function writeYBlock(
  Y: Float64Array,
  width: number,
  bx: number,
  by: number,
  block: Float64Array,
): void {
  for (let y = 0; y < BLOCK; y++) {
    for (let x = 0; x < BLOCK; x++) {
      Y[(by * BLOCK + y) * width + (bx * BLOCK + x)] = Math.max(
        0,
        Math.min(255, block[y * BLOCK + x]!),
      );
    }
  }
}

function pixelsToYCbCrPlanes(pixels: PixelBuffer) {
  const n = pixels.width * pixels.height;
  const Y = new Float64Array(n);
  const Cb = new Float64Array(n);
  const Cr = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const o = i * 4;
    const c = rgbToYCbCr(
      pixels.data[o]!,
      pixels.data[o + 1]!,
      pixels.data[o + 2]!,
    );
    Y[i] = c.Y;
    Cb[i] = c.Cb;
    Cr[i] = c.Cr;
  }
  return { Y, Cb, Cr };
}

function planesToPixels(
  pixels: PixelBuffer,
  Y: Float64Array,
  Cb: Float64Array,
  Cr: Float64Array,
): void {
  const n = pixels.width * pixels.height;
  for (let i = 0; i < n; i++) {
    const rgb = yCbCrToRgb(Y[i]!, Cb[i]!, Cr[i]!);
    const o = i * 4;
    pixels.data[o] = rgb.r;
    pixels.data[o + 1] = rgb.g;
    pixels.data[o + 2] = rgb.b;
    // keep alpha
  }
}

/**
 * Embed payload bits into the Y channel via DCT-QIM with repetition
 * across a keyed pseudo-random block order.
 */
export function embed(
  pixels: PixelBuffer,
  payloadBits: number[],
  options: EmbedOptions,
): PixelBuffer {
  const step = options.step ?? 24;
  const out = clonePixels(pixels);
  const { Y, Cb, Cr } = pixelsToYCbCrPlanes(out);
  const { cols, rows, total } = blockCount(out.width, out.height);
  if (total < PAYLOAD_BITS) {
    throw new Error(
      `Image too small for watermark (${total} blocks < ${PAYLOAD_BITS} bits)`,
    );
  }

  const bits =
    payloadBits.length === PAYLOAD_BITS
      ? payloadBits
      : payloadBits.slice(0, PAYLOAD_BITS);
  while (bits.length < PAYLOAD_BITS) bits.push(0);

  const order = shuffledBlockOrder(total, options.key);
  const reps = Math.floor(total / PAYLOAD_BITS);

  for (let r = 0; r < reps; r++) {
    for (let bi = 0; bi < PAYLOAD_BITS; bi++) {
      const flat = order[r * PAYLOAD_BITS + bi]!;
      const bx = flat % cols;
      const by = Math.floor(flat / cols);
      if (by >= rows) continue;

      const spatial = readYBlock(Y, out.width, bx, by);
      // Level-shift for DCT
      for (let i = 0; i < spatial.length; i++) spatial[i]! -= 128;
      const coeffs = dct2d(spatial, BLOCK);
      const idx = MID_V * BLOCK + MID_U;
      coeffs[idx] = qimEmbed(coeffs[idx]!, bits[bi]!, step);
      const recon = idct2d(coeffs, BLOCK);
      for (let i = 0; i < recon.length; i++) recon[i]! += 128;
      writeYBlock(Y, out.width, bx, by, recon);
    }
  }

  planesToPixels(out, Y, Cb, Cr);
  return out;
}

/** Embed a certificate ID payload into pixels. */
export function embedCertId(
  pixels: PixelBuffer,
  certId: string,
  options: EmbedOptions,
): { pixels: PixelBuffer; payloadBits: number[] } {
  const payloadBits = encodePayload(certId);
  return { pixels: embed(pixels, payloadBits, options), payloadBits };
}

/**
 * Extract payload via majority vote over repeated QIM block readings.
 * confidence = fraction of block votes agreeing with the majority bit.
 */
export function extract(
  pixels: PixelBuffer,
  options: EmbedOptions,
): ExtractResult {
  const step = options.step ?? 24;
  const { Y } = pixelsToYCbCrPlanes(pixels);
  const { cols, rows, total } = blockCount(pixels.width, pixels.height);
  if (total < PAYLOAD_BITS) {
    return { payload: "", payloadBits: [], confidence: 0 };
  }

  const order = shuffledBlockOrder(total, options.key);
  const reps = Math.floor(total / PAYLOAD_BITS);
  const votes: number[][] = Array.from({ length: PAYLOAD_BITS }, () => []);

  for (let r = 0; r < reps; r++) {
    for (let bi = 0; bi < PAYLOAD_BITS; bi++) {
      const flat = order[r * PAYLOAD_BITS + bi]!;
      const bx = flat % cols;
      const by = Math.floor(flat / cols);
      if (by >= rows) continue;

      const spatial = readYBlock(Y, pixels.width, bx, by);
      for (let i = 0; i < spatial.length; i++) spatial[i]! -= 128;
      const coeffs = dct2d(spatial, BLOCK);
      const bit = qimExtract(coeffs[MID_V * BLOCK + MID_U]!, step);
      votes[bi]!.push(bit);
    }
  }

  const payloadBits: number[] = [];
  let agree = 0;
  let totalVotes = 0;

  for (let bi = 0; bi < PAYLOAD_BITS; bi++) {
    const v = votes[bi]!;
    let ones = 0;
    for (const b of v) {
      if (b === 1) ones++;
    }
    const zeros = v.length - ones;
    const majority = ones >= zeros ? 1 : 0;
    payloadBits.push(majority);
    const majorityCount = majority === 1 ? ones : zeros;
    agree += majorityCount;
    totalVotes += v.length;
  }

  const confidence = totalVotes === 0 ? 0 : agree / totalVotes;
  const decoded = decodePayload(payloadBits);
  return {
    payload: decoded ?? "",
    payloadBits,
    confidence,
  };
}

/** Stable digest of payload bits for storage. */
export function payloadBitsDigest(bits: number[]): string {
  return createHash("sha256").update(Buffer.from(bits)).digest("hex").slice(0, 16);
}
