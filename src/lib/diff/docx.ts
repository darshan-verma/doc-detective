import mammoth from "mammoth";
import { diffText } from "./text";
import type { DiffResult } from "./types";

async function extractDocxText(data: Buffer): Promise<string> {
  const result = await mammoth.extractRawText({ buffer: data });
  return result.value;
}

export async function diffDocx(
  original: Buffer,
  uploaded: Buffer,
): Promise<DiffResult> {
  try {
    const [origText, upText] = await Promise.all([
      extractDocxText(original),
      extractDocxText(uploaded),
    ]);
    const result = diffText(
      origText,
      upText,
      original.length,
      uploaded.length,
      "docx",
    );
    if (result.changes.length === 0 && original.length !== uploaded.length) {
      result.note =
        "Extracted DOCX text is identical but file bytes differ (formatting, metadata, or embedded objects may have changed).";
    }
    return result;
  } catch (err) {
    return {
      type: "docx",
      summary: "DOCX text extraction failed",
      changes: [],
      originalSize: original.length,
      uploadedSize: uploaded.length,
      note: `Could not extract DOCX text (${err instanceof Error ? err.message : "unknown error"}).`,
    };
  }
}
