import { writeFileSync, mkdirSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function buildPdf(pageTexts) {
  const objects = [];
  // 1: Catalog
  objects[1] = `<< /Type /Catalog /Pages 2 0 R >>`;
  // 2: Pages (filled later)
  const pageObjNums = pageTexts.map((_, i) => 3 + i * 2);
  // Font is last object after pages+contents
  const fontObj = 3 + pageTexts.length * 2;

  const kids = pageObjNums.map((n) => `${n} 0 R`).join(" ");
  objects[2] = `<< /Type /Pages /Kids [${kids}] /Count ${pageTexts.length} >>`;

  for (let i = 0; i < pageTexts.length; i++) {
    const pageNum = pageObjNums[i];
    const contentNum = pageNum + 1;
    const text = pageTexts[i];
    const stream = `BT /F1 12 Tf 72 720 Td (${text.replace(/[\\()]/g, "\\$&")}) Tj ET`;
    objects[pageNum] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
      `/Contents ${contentNum} 0 R /Resources << /Font << /F1 ${fontObj} 0 R >> >> >>`;
    objects[contentNum] = `<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`;
  }
  objects[fontObj] = `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`;

  let body = "%PDF-1.4\n";
  const offsets = [0];
  for (let i = 1; i < objects.length; i++) {
    offsets[i] = Buffer.byteLength(body);
    body += `${i} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefStart = Buffer.byteLength(body);
  body += `xref\n0 ${objects.length}\n`;
  body += `0000000000 65535 f \n`;
  for (let i = 1; i < objects.length; i++) {
    body += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  body += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\n`;
  body += `startxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(body);
}

const outDir = path.join(__dirname, "../tests/fixtures");
mkdirSync(outDir, { recursive: true });

const sample = buildPdf(["Hello Page One", "Hello Page Two"]);
writeFileSync(path.join(outDir, "sample.pdf"), sample);
console.log("Wrote sample.pdf", sample.length, "bytes");
