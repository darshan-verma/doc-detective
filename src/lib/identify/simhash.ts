import { createHash } from "crypto";

/**
 * 64-bit Charikar SimHash over whitespace-normalized tokens.
 * Returns 16-char lowercase hex.
 */
export function textSimhash64(text: string): string {
  const tokens = tokenize(text);
  if (tokens.length === 0) {
    return "0".repeat(16);
  }

  const weights = new Array<number>(64).fill(0);
  for (const token of tokens) {
    const bits = tokenHashBits(token);
    for (let i = 0; i < 64; i++) {
      weights[i]! += bits[i] ? 1 : -1;
    }
  }

  let hex = "";
  for (let i = 0; i < 64; i += 4) {
    const nibble =
      ((weights[i]! >= 0 ? 1 : 0) << 3) |
      ((weights[i + 1]! >= 0 ? 1 : 0) << 2) |
      ((weights[i + 2]! >= 0 ? 1 : 0) << 1) |
      (weights[i + 3]! >= 0 ? 1 : 0);
    hex += nibble.toString(16);
  }
  return hex;
}

/** Hamming distance between two 64-bit hex SimHashes. */
export function simhashHamming(a: string, b: string): number {
  const ba = hexToBits64(a);
  const bb = hexToBits64(b);
  let d = 0;
  for (let i = 0; i < 64; i++) {
    if (ba[i] !== bb[i]) d++;
  }
  return d;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim()
    .split(/[^a-z0-9]+/i)
    .filter((t) => t.length > 0);
}

function tokenHashBits(token: string): boolean[] {
  const digest = createHash("sha256").update(token, "utf8").digest();
  const bits: boolean[] = [];
  for (let i = 0; i < 8; i++) {
    const byte = digest[i]!;
    for (let b = 7; b >= 0; b--) {
      bits.push(((byte >> b) & 1) === 1);
    }
  }
  return bits;
}

function hexToBits64(hex: string): number[] {
  const bits: number[] = [];
  const h = hex.padStart(16, "0").slice(0, 16);
  for (const ch of h) {
    const n = parseInt(ch, 16);
    if (Number.isNaN(n)) {
      bits.push(0, 0, 0, 0);
      continue;
    }
    bits.push((n >> 3) & 1, (n >> 2) & 1, (n >> 1) & 1, n & 1);
  }
  return bits;
}
