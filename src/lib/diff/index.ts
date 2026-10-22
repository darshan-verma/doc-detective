import path from "path";
import { diffBinary, diffImage } from "./binary";
import { diffDocx } from "./docx";
import { diffPdf } from "./pdf";
import { diffText } from "./text";
import type { DiffResult } from "./types";

export type {
  DiffResult,
  DiffStatus,
  LineChange,
  PageChange,
  ByteRangeChange,
  WordChange,
  DiffCounts,
} from "./types";
export { normalizeText, smartLineDiff, diffText } from "./text";
export { extractPdfPages, itemsToReadingOrderText } from "./pdf";

const TEXT_EXTS = new Set([
  ".txt",
  ".md",
  ".csv",
  ".json",
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".c",
  ".cpp",
  ".h",
  ".css",
  ".html",
  ".xml",
  ".yml",
  ".yaml",
  ".toml",
  ".ini",
  ".sh",
  ".env",
  ".log",
]);

const IMAGE_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".tif",
  ".tiff",
]);

function isTextMime(mime: string): boolean {
  return mime.startsWith("text/") || mime === "application/json";
}

function isImageMime(mime: string): boolean {
  return mime.startsWith("image/");
}

export async function diffFiles(options: {
  original: Buffer;
  uploaded: Buffer;
  originalName: string;
  mimeType: string;
  chunkHashes?: string[];
}): Promise<DiffResult> {
  const { original, uploaded, originalName, mimeType, chunkHashes } = options;
  const ext = path.extname(originalName).toLowerCase();

  if (ext === ".pdf" || mimeType === "application/pdf") {
    return diffPdf(original, uploaded);
  }

  if (
    ext === ".docx" ||
    mimeType ===
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  ) {
    return diffDocx(original, uploaded);
  }

  if (TEXT_EXTS.has(ext) || isTextMime(mimeType)) {
    return diffText(
      original.toString("utf8"),
      uploaded.toString("utf8"),
      original.length,
      uploaded.length,
      "text",
    );
  }

  if (IMAGE_EXTS.has(ext) || isImageMime(mimeType)) {
    return diffImage(original, uploaded, mimeType, chunkHashes);
  }

  return diffBinary(original, uploaded, chunkHashes);
}
