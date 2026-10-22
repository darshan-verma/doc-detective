import path from "path";
import { pathToFileURL } from "url";
import { smartLineDiff } from "./text";
import type { DiffCounts, DiffResult, PageChange } from "./types";

interface TextItem {
  str: string;
  transform: number[];
}

const Y_LINE_THRESHOLD = 3;

const ANALYSIS_UNAVAILABLE_MESSAGE = "Could not analyze content; bytes differ";

/**
 * Extract PDF text per page with pdfjs-dist.
 * Items are sorted by y (top→bottom) then x (left→right) so reading
 * order is stable regardless of internal content-stream order.
 */
export async function extractPdfPages(
  data: Buffer,
): Promise<{ pages: string[]; numpages: number; text: string }> {
  // Dynamic import inside the function (not module top-level).
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");

  const workerPath = path.join(
    process.cwd(),
    "node_modules",
    "pdfjs-dist",
    "legacy",
    "build",
    "pdf.worker.mjs",
  );
  pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(workerPath).href;

  const loadingTask = pdfjs.getDocument({
    data: new Uint8Array(data),
    useSystemFonts: true,
    disableFontFace: true,
  });

  const pdf = await loadingTask.promise;
  const pages: string[] = [];

  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
    const page = await pdf.getPage(pageNum);
    const content = await page.getTextContent();
    const items = (content.items as TextItem[]).filter(
      (item) => typeof item.str === "string" && item.str.length > 0,
    );

    pages.push(itemsToReadingOrderText(items));
  }

  return {
    pages,
    numpages: pdf.numPages,
    text: pages.join("\f"),
  };
}

/** Sort by y desc (PDF origin bottom-left), then x asc; group into lines. */
export function itemsToReadingOrderText(items: TextItem[]): string {
  if (items.length === 0) return "";

  const sorted = [...items].sort((a, b) => {
    const ay = a.transform[5] ?? 0;
    const by = b.transform[5] ?? 0;
    if (Math.abs(ay - by) > Y_LINE_THRESHOLD) {
      return by - ay; // higher y first (top of page)
    }
    const ax = a.transform[4] ?? 0;
    const bx = b.transform[4] ?? 0;
    return ax - bx;
  });

  const lines: string[] = [];
  let currentY = sorted[0]!.transform[5] ?? 0;
  let currentParts: string[] = [];

  for (const item of sorted) {
    const y = item.transform[5] ?? 0;
    if (Math.abs(y - currentY) > Y_LINE_THRESHOLD) {
      const line = currentParts.join("").replace(/ +/g, " ").trim();
      if (line) lines.push(line);
      currentParts = [];
      currentY = y;
    }
    currentParts.push(item.str);
  }

  const last = currentParts.join("").replace(/ +/g, " ").trim();
  if (last) lines.push(last);

  return lines.join("\n");
}

function emptyCounts(): DiffCounts {
  return { added: 0, removed: 0, changed: 0, moved: 0 };
}

function addCounts(a: DiffCounts, b: DiffCounts): DiffCounts {
  return {
    added: a.added + b.added,
    removed: a.removed + b.removed,
    changed: a.changed + b.changed,
    moved: a.moved + b.moved,
  };
}

function analysisUnavailable(
  originalSize: number,
  uploadedSize: number,
): DiffResult {
  return {
    type: "pdf",
    status: "ANALYSIS_UNAVAILABLE",
    summary: ANALYSIS_UNAVAILABLE_MESSAGE,
    message: ANALYSIS_UNAVAILABLE_MESSAGE,
    changes: [],
    originalSize,
    uploadedSize,
    note: ANALYSIS_UNAVAILABLE_MESSAGE,
  };
}

export async function diffPdf(
  original: Buffer,
  uploaded: Buffer,
): Promise<DiffResult> {
  let origExtract;
  let upExtract;
  try {
    [origExtract, upExtract] = await Promise.all([
      extractPdfPages(original),
      extractPdfPages(uploaded),
    ]);
  } catch {
    return analysisUnavailable(original.length, uploaded.length);
  }

  const maxPages = Math.max(origExtract.pages.length, upExtract.pages.length);
  const pageChanges: PageChange[] = [];
  let totals = emptyCounts();
  let formattingOnlyDifferencesIgnored = false;

  for (let i = 0; i < maxPages; i++) {
    const o = origExtract.pages[i] ?? "";
    const u = upExtract.pages[i] ?? "";
    const smart = smartLineDiff(o, u);
    formattingOnlyDifferencesIgnored =
      formattingOnlyDifferencesIgnored ||
      smart.formattingOnlyDifferencesIgnored;
    totals = addCounts(totals, smart.counts);

    if (
      smart.changes.length === 0 &&
      smart.moved.length === 0 &&
      !smart.formattingOnlyDifferencesIgnored
    ) {
      continue;
    }

    if (smart.changes.length === 0 && smart.moved.length === 0) {
      continue;
    }

    const { added, removed, changed, moved } = smart.counts;
    pageChanges.push({
      page: i + 1,
      changes: smart.changes,
      moved: smart.moved,
      counts: smart.counts,
      formattingOnlyDifferencesIgnored: smart.formattingOnlyDifferencesIgnored,
      summary: `${added} added, ${removed} removed, ${changed} changed, ${moved} moved`,
    });
  }

  const hasSubstance =
    totals.added + totals.removed + totals.changed + totals.moved > 0;

  const result: DiffResult = {
    type: "pdf",
    summary: hasSubstance
      ? `${pageChanges.length} page(s): ${totals.added} added, ${totals.removed} removed, ${totals.changed} changed, ${totals.moved} moved`
      : "No textual differences across pages",
    changes: pageChanges,
    originalSize: original.length,
    uploadedSize: uploaded.length,
    pageCount: {
      original: origExtract.numpages,
      uploaded: upExtract.numpages,
    },
    counts: totals,
    formattingOnlyDifferencesIgnored,
  };

  if (!hasSubstance && original.length !== uploaded.length) {
    result.note = formattingOnlyDifferencesIgnored
      ? "Only formatting/whitespace differences were found and ignored. File bytes still differ (common after re-saving a PDF)."
      : "Extracted PDF text is identical after normalization but file bytes differ — common after re-saving or compressing a PDF.";
  }

  return result;
}
