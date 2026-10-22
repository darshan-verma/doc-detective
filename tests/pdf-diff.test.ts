import { readFileSync } from "fs";
import path from "path";
import { describe, expect, it } from "vitest";
import {
  diffPdf,
  extractPdfPages,
  itemsToReadingOrderText,
} from "../src/lib/diff/pdf";
import { smartLineDiff } from "../src/lib/diff/text";

const fixturePath = path.join(__dirname, "fixtures", "sample.pdf");

describe("pdf reading order", () => {
  it("sorts items by y then x regardless of storage order", () => {
    const items = [
      { str: "right", transform: [1, 0, 0, 1, 200, 100] },
      { str: "left", transform: [1, 0, 0, 1, 10, 100] },
      { str: "below", transform: [1, 0, 0, 1, 10, 50] },
    ];
    const text = itemsToReadingOrderText(items);
    expect(text).toBe("leftright\nbelow");
  });
});

describe("pdf-oriented smart diff", () => {
  it("ignores NBSP / multi-space churn typical of re-saved PDFs", () => {
    const pageA = "Invoice\u00A0#100\nTotal:  $12.00";
    const pageB = "Invoice #100\nTotal: $12.00";
    const result = smartLineDiff(pageA, pageB);
    expect(result.changes).toHaveLength(0);
    expect(result.moved).toHaveLength(0);
    expect(result.formattingOnlyDifferencesIgnored).toBe(true);
  });
});

describe("pdfjs extraction", () => {
  it("extracts expected text per page from the sample fixture", async () => {
    const buf = readFileSync(fixturePath);
    const result = await extractPdfPages(buf);
    expect(result.numpages).toBe(2);
    expect(result.pages[0]).toContain("Hello Page One");
    expect(result.pages[1]).toContain("Hello Page Two");
  });

  it("returns ANALYSIS_UNAVAILABLE for a corrupt PDF", async () => {
    const original = readFileSync(fixturePath);
    const corrupt = Buffer.from("%PDF-1.4\nthis is not a valid pdf payload");
    const result = await diffPdf(original, corrupt);
    expect(result.status).toBe("ANALYSIS_UNAVAILABLE");
    expect(result.message).toBe("Could not analyze content; bytes differ");
    expect(result.summary).toBe("Could not analyze content; bytes differ");
    expect(result.summary).not.toContain("No page-level text changes");
    expect(result.changes).toEqual([]);
  });
});
