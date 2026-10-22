import { randomBytes, timingSafeEqual } from "crypto";

/** Crockford-like base32 without ambiguous characters (I, L, O, U). */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Legacy short IDs (pre–trust-layer). */
const LEGACY_ID_RE = /^[A-Za-z0-9]{6,8}$/;

/** Compact 26-char base32 encoding of 128 random bits. */
const COMPACT_ID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/i;

/**
 * Generate a 128-bit certificate ID as compact base32 (26 chars).
 * Display with {@link formatCertId}.
 */
export function generateCertId(): string {
  const bytes = randomBytes(16);
  return encodeBase32(bytes);
}

/** Encode 16 bytes → 26 base32 chars (padding-free). */
export function encodeBase32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 31];
  }
  // 16 bytes → 26 chars exactly for our alphabet packing
  return out.slice(0, 26);
}

/**
 * Display form: DD-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
 * (prefix + 26 chars in groups of 4).
 */
export function formatCertId(compact: string): string {
  const c = normalizeCertId(compact);
  if (!c || isLegacyCertId(c)) return compact.toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < c.length; i += 4) {
    groups.push(c.slice(i, i + 4));
  }
  return `DD-${groups.join("-")}`;
}

/** Strip DD- prefix and dashes; uppercase. Returns null if malformed. */
export function normalizeCertId(input: string): string | null {
  if (!input || typeof input !== "string") return null;
  let s = input.trim().toUpperCase().replace(/[\s_]/g, "");
  if (s.startsWith("DD-")) s = s.slice(3);
  s = s.replace(/-/g, "");
  if (LEGACY_ID_RE.test(s)) return s;
  if (COMPACT_ID_RE.test(s)) return s;
  return null;
}

export function isLegacyCertId(id: string): boolean {
  return LEGACY_ID_RE.test(id) && !COMPACT_ID_RE.test(id);
}

export function isValidCertIdFormat(input: string): boolean {
  return normalizeCertId(input) !== null;
}

/**
 * Constant-time-ish comparison helper for NOT_FOUND responses.
 * Pads both sides so length differences do not short-circuit early.
 */
export function constantTimeEqualString(a: string, b: string): boolean {
  const max = Math.max(a.length, b.length, 1);
  const ba = Buffer.alloc(max, 0);
  const bb = Buffer.alloc(max, 0);
  Buffer.from(a).copy(ba);
  Buffer.from(b).copy(bb);
  return timingSafeEqual(ba, bb) && a.length === b.length;
}

/** 8-char watermark token derived from a full cert ID (legacy or compact). */
export function watermarkTokenFromCertId(certId: string): string {
  const compact = normalizeCertId(certId) ?? certId.toUpperCase();
  if (compact.length <= 8) return compact.padEnd(8, "0").slice(0, 8);
  return compact.slice(0, 8);
}
