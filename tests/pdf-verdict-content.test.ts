import { PDFDocument } from "pdf-lib";
import { PNG } from "pngjs";
import { describe, expect, it } from "vitest";
import { PdfAnalyzer } from "../src/lib/analysis/pdf/analyzer";
import { Verdict } from "../src/lib/analysis/types";
import { explainAnalysis } from "../src/lib/explain";

async function pdfWithText(
  text: string,
  meta?: { title?: string; producer?: string },
): Promise<Buffer> {
  const doc = await PDFDocument.create();
  if (meta?.title) doc.setTitle(meta.title);
  if (meta?.producer) doc.setProducer(meta.producer);
  const page = doc.addPage([400, 400]);
  page.drawText(text, { x: 40, y: 350, size: 12 });
  return Buffer.from(await doc.save());
}

function tinyPng(r: number, g: number, b: number): Buffer {
  const png = new PNG({ width: 8, height: 8 });
  for (let i = 0; i < png.data.length; i += 4) {
    png.data[i] = r;
    png.data[i + 1] = g;
    png.data[i + 2] = b;
    png.data[i + 3] = 255;
  }
  return PNG.sync.write(png);
}

async function pdfWithTextAndImage(
  text: string,
  color: [number, number, number],
): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([400, 400]);
  page.drawText(text, { x: 40, y: 350, size: 12 });
  const img = await doc.embedPng(tinyPng(...color));
  page.drawImage(img, { x: 40, y: 200, width: 80, height: 80 });
  return Buffer.from(await doc.save());
}

describe("PDF verdict: content vs format", () => {
  const analyzer = new PdfAnalyzer();

  it("metadata-only change → MODIFIED_FORMAT_ONLY with no failed content checks", async () => {
    const original = await pdfWithText("Same body text", {
      title: "Original",
      producer: "Producer A",
    });
    const uploaded = await pdfWithText("Same body text", {
      title: "Re-saved",
      producer: "Producer B",
    });

    const result = await analyzer.analyze(original, uploaded);
    expect(result.verdict).toBe(Verdict.MODIFIED_FORMAT_ONLY);
    expect(result.formatDifferences?.length).toBeGreaterThan(0);

    const contentNames = new Set([
      "text",
      "visual",
      "embedded-images",
      "annotations",
      "form-fields",
    ]);
    const failedContent = result.checks.filter(
      (c) => contentNames.has(c.name) && c.status === "FAILED",
    );
    expect(failedContent).toEqual([]);
  }, 60_000);

  it("text edit + image removal → TAMPERED; headline mentions text and image", async () => {
    const original = await pdfWithTextAndImage(
      "Principal Researcher Resume Document Page One",
      [200, 50, 50],
    );
    const uploaded = await pdfWithText(
      "Darshan Verma Research Profile Document Page One",
    );

    const result = await analyzer.analyze(original, uploaded);
    expect(result.verdict).toBe(Verdict.TAMPERED);

    const imgCheck = result.checks.find((c) => c.name === "embedded-images");
    expect(imgCheck?.status).toBe("FAILED");
    expect(imgCheck?.detail?.toLowerCase()).toMatch(/removed|image/);

    const textCheck = result.checks.find((c) => c.name === "text");
    expect(textCheck?.status).toBe("FAILED");

    const plain = explainAnalysis(result);
    expect(plain.headline).toBe("Tampered");
    expect(plain.explanation.toLowerCase()).toMatch(/text/);
    expect(plain.explanation.toLowerCase()).toMatch(/image/);
  }, 90_000);
});
