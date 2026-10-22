import path from "path";
import { extractPdfPages } from "../diff/pdf";

/** Extract plain text for SimHash from PDF / DOCX / TXT-like uploads. */
export async function extractTextForSimhash(
  bytes: Buffer,
  filename: string,
  mimeType: string,
): Promise<string | null> {
  const ext = path.extname(filename).toLowerCase();
  const mime = (mimeType || "").toLowerCase();

  if (mime === "application/pdf" || ext === ".pdf") {
    const { text } = await extractPdfPages(bytes);
    return text || null;
  }

  if (
    mime.includes("wordprocessingml") ||
    ext === ".docx"
  ) {
    const mammoth = await import("mammoth");
    const result = await mammoth.extractRawText({ buffer: bytes });
    return result.value || null;
  }

  if (
    mime.startsWith("text/") ||
    [".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm"].includes(ext)
  ) {
    return bytes.toString("utf8");
  }

  return null;
}

export function isDocumentForSimhash(
  filename: string,
  mimeType: string,
): boolean {
  const ext = path.extname(filename).toLowerCase();
  const mime = (mimeType || "").toLowerCase();
  if (mime === "application/pdf" || ext === ".pdf") return true;
  if (mime.includes("wordprocessingml") || ext === ".docx") return true;
  if (mime.startsWith("text/")) return true;
  return [".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm"].includes(ext);
}
