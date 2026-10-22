import JSZip from "jszip";
import { describe, expect, it } from "vitest";
import { DocxAnalyzer } from "../src/lib/analysis/office/docx";
import { XlsxAnalyzer } from "../src/lib/analysis/office/xlsx";
import { Verdict } from "../src/lib/analysis/types";

async function minimalDocx(bodyText: string, creator = "Test"): Promise<Buffer> {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`,
  );
  zip.file(
    "docProps/core.xml",
    `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>${creator}</dc:creator></cp:coreProperties>`,
  );
  zip.file(
    "word/document.xml",
    `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${bodyText}</w:t></w:r></w:p></w:body></w:document>`,
  );
  return zip.generateAsync({ type: "nodebuffer" });
}

async function minimalXlsx(
  cells: Record<string, string>,
): Promise<Buffer> {
  const zip = new JSZip();
  zip.file(
    "[Content_Types].xml",
    `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`,
  );
  zip.file(
    "docProps/core.xml",
    `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Test</dc:creator></cp:coreProperties>`,
  );
  zip.file(
    "xl/workbook.xml",
    `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>`,
  );
  const cellXml = Object.entries(cells)
    .map(
      ([ref, val]) =>
        val.startsWith("=")
          ? `<c r="${ref}"><f>${val.slice(1)}</f><v>0</v></c>`
          : `<c r="${ref}"><v>${val}</v></c>`,
    )
    .join("");
  zip.file(
    "xl/worksheets/sheet1.xml",
    `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row>${cellXml}</row></sheetData></worksheet>`,
  );
  return zip.generateAsync({ type: "nodebuffer" });
}

describe("DocxAnalyzer", () => {
  it("detects text tampering", async () => {
    const a = await minimalDocx("Hello");
    const b = await minimalDocx("Hello changed");
    const result = await new DocxAnalyzer().analyze(a, b);
    expect(result.verdict).toBe(Verdict.TAMPERED);
  });

  it("detects metadata-only as MODIFIED_FORMAT_ONLY", async () => {
    const a = await minimalDocx("Same", "Alice");
    const b = await minimalDocx("Same", "Bob");
    const result = await new DocxAnalyzer().analyze(a, b);
    expect(result.verdict).toBe(Verdict.MODIFIED_FORMAT_ONLY);
  });
});

describe("XlsxAnalyzer", () => {
  it("detects formula/value change", async () => {
    const a = await minimalXlsx({ A1: "1", B1: "=A1+1" });
    const b = await minimalXlsx({ A1: "1", B1: "=A1+2" });
    const result = await new XlsxAnalyzer().analyze(a, b);
    expect(result.verdict).toBe(Verdict.TAMPERED);
    expect(
      result.changes.some(
        (c) => c.location?.includes("B1") || c.kind === "cell",
      ),
    ).toBe(true);
  });
});
