/**
 * Generate synthetic corpus fixtures for `npm run eval`.
 * Real editor-saved files should replace these over time for threshold tuning.
 */
import { mkdir, writeFile } from "fs/promises";
import path from "path";
import JSZip from "jszip";
import sharp from "sharp";

const root = path.join(process.cwd(), "tests/corpus/fixtures");

async function docx(text: string, creator: string): Promise<Buffer> {
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
    `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:body></w:document>`,
  );
  return zip.generateAsync({ type: "nodebuffer" });
}

async function xlsx(formula: string): Promise<Buffer> {
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
    `<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Sheet1" sheetId="1"/></sheets></workbook>`,
  );
  zip.file(
    "xl/worksheets/sheet1.xml",
    `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c r="A1"><v>1</v></c><c r="B1"><f>${formula}</f><v>0</v></c></row></sheetData></worksheet>`,
  );
  return zip.generateAsync({ type: "nodebuffer" });
}

async function main() {
  await mkdir(root, { recursive: true });

  await writeFile(path.join(root, "note.txt"), "The quick brown fox\n");
  await writeFile(
    path.join(root, "note-changed.txt"),
    "The quick red fox\n",
  );
  await writeFile(
    path.join(root, "note-crlf.txt"),
    "The quick brown fox\r\n",
  );

  const png = await sharp({
    create: {
      width: 64,
      height: 64,
      channels: 3,
      background: { r: 40, g: 120, b: 200 },
    },
  })
    .png()
    .toBuffer();
  await writeFile(path.join(root, "dot.png"), png);

  // Same pixels, different PNG compression → format-only when decoded
  const reenc = await sharp(png).png({ compressionLevel: 9 }).toBuffer();
  await writeFile(path.join(root, "dot-reencoded.png"), reenc);

  const edited = await sharp(png)
    .composite([
      {
        input: await sharp({
          create: {
            width: 16,
            height: 16,
            channels: 3,
            background: { r: 255, g: 0, b: 0 },
          },
        })
          .png()
          .toBuffer(),
        top: 24,
        left: 24,
      },
    ])
    .png()
    .toBuffer();
  await writeFile(path.join(root, "dot-edited.png"), edited);

  await writeFile(path.join(root, "letter.docx"), await docx("Dear Sir", "Alice"));
  await writeFile(
    path.join(root, "letter-changed.docx"),
    await docx("Dear Madam", "Alice"),
  );
  await writeFile(
    path.join(root, "letter-meta.docx"),
    await docx("Dear Sir", "Bob"),
  );

  await writeFile(path.join(root, "sheet.xlsx"), await xlsx("A1+1"));
  await writeFile(path.join(root, "sheet-formula.xlsx"), await xlsx("A1+99"));

  console.log("Corpus fixtures written to", root);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
