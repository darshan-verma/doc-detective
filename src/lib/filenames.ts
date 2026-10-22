import path from "path";
import { PLATFORM_NAME } from "./config";
import { normalizeCertId } from "./trust/ids";

const UNSAFE = /[<>:"/\\|?*\x00-\x1f]/g;

/** Strip path traversal and unsafe characters from a client filename. */
export function sanitizeFilename(name: string): string {
  const base = path.basename(name || "file").replace(UNSAFE, "_").trim();
  if (!base || base === "." || base === "..") return "file";
  // Cap length to avoid filesystem / header issues
  return base.slice(0, 200);
}

export function splitNameExt(filename: string): { basename: string; ext: string } {
  const sanitized = sanitizeFilename(filename);
  const ext = path.extname(sanitized);
  const basename = ext ? sanitized.slice(0, -ext.length) : sanitized;
  return { basename: basename || "file", ext };
}

/**
 * report.pdf + K7X2M9 -> report_doc-detective_K7X2M9.pdf
 * For certified images, forceExt=".png" → report_doc-detective_K7X2M9.png
 */
export function certifiedFilename(
  originalName: string,
  certId: string,
  options?: { forceExt?: string },
): string {
  const { basename, ext } = splitNameExt(originalName);
  const outExt = options?.forceExt ?? ext;
  return `${basename}_${PLATFORM_NAME}_${certId}${outExt}`;
}

/**
 * Parse certId from a certified filename pattern:
 * anything_doc-detective_<certId>.ext
 */
export function parseCertIdFromFilename(filename: string): string | null {
  const sanitized = sanitizeFilename(filename);
  const { basename } = splitNameExt(sanitized);
  const marker = `_${PLATFORM_NAME}_`;
  const idx = basename.lastIndexOf(marker);
  if (idx === -1) return null;
  const raw = basename.slice(idx + marker.length);
  return normalizeCertId(raw);
}
