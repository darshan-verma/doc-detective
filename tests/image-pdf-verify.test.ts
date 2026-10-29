import { createHash, generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import { PDFDocument, PDFString, rgb, StandardFonts } from "pdf-lib";
import sharp from "sharp";
import { resetConfigCache } from "../src/lib/config";
import { LocalDiskStorage, setStorage } from "../src/lib/storage";
import { certifyUpload } from "../src/lib/certificates/service";
import { verifyUpload } from "../src/lib/verify/service";
import { decodeImage } from "../src/lib/image";
import { PDF_IMAGE_UNAVAILABLE_MESSAGE } from "../src/lib/image/from-pdf";
import { diffBinary, diffImage, readImageDimensions } from "../src/lib/diff/binary";
import { resetSigningKeyCache } from "../src/lib/signing";
import type { PixelBuffer } from "../src/lib/image/pixels";

const prisma = new PrismaClient();
let storageDir: string;
let privatePem: string;

beforeAll(() => {
  const { privateKey } = generateKeyPairSync("ed25519");
  privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  storageDir = mkdtempSync(path.join(tmpdir(), "doc-detective-img-pdf-"));
  process.env.ED25519_PRIVATE_KEY = privatePem;
  process.env.WATERMARK_KEY = "test-watermark-key-value";
  process.env.MAX_UPLOAD_MB = "25";
  process.env.STORAGE_DIR = storageDir;
  process.env.DATABASE_URL =
    process.env.DATABASE_URL || "file:./prisma/dev.db";
  process.env.TAMPER_SCORE_ALERT = "1.5";
  process.env.IMAGE_GRID_SIZE = "8";
  resetConfigCache();
  resetSigningKeyCache();
  setStorage(new LocalDiskStorage(storageDir));
});

afterAll(async () => {
  await prisma.$disconnect();
  rmSync(storageDir, { recursive: true, force: true });
  setStorage(null);
  resetConfigCache();
  resetSigningKeyCache();
});

async function texturedImage(width = 128, height = 128): Promise<Buffer> {
  const raw = Buffer.alloc(width * height * 3);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 3;
      raw[i] = (x * 3 + y) % 256;
      raw[i + 1] = (x * 7 + y * 5) % 256;
      raw[i + 2] = (x * 11 + y * 13) % 256;
    }
  }
  return sharp(raw, { raw: { width, height, channels: 3 } })
    .png()
    .toBuffer();
}

function makeFile(buf: Buffer, name: string, type = "image/png") {
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  return new File([ab as ArrayBuffer], name, { type });
}

async function paintRect(
  pixels: PixelBuffer,
  x0: number,
  y0: number,
  w: number,
  h: number,
  rgb: [number, number, number],
): Promise<PixelBuffer> {
  const out: PixelBuffer = {
    data: new Uint8ClampedArray(pixels.data),
    width: pixels.width,
    height: pixels.height,
  };
  for (let y = y0; y < y0 + h && y < out.height; y++) {
    for (let x = x0; x < x0 + w && x < out.width; x++) {
      const i = (y * out.width + x) * 4;
      out.data[i] = rgb[0];
      out.data[i + 1] = rgb[1];
      out.data[i + 2] = rgb[2];
    }
  }
  return out;
}

async function loadCertifiedPng(certId: string): Promise<Buffer> {
  const stored = await prisma.certificate.findUniqueOrThrow({
    where: { certId },
  });
  const storage = new LocalDiskStorage(storageDir);
  const stream = await storage.get(stored.storagePath);
  const chunks: Buffer[] = [];
  for await (const c of stream) {
    chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  }
  return Buffer.concat(chunks);
}

async function embedPngInPdf(
  pngBytes: Buffer,
  pages = 1,
): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const png = await pdfDoc.embedPng(pngBytes);
  for (let i = 0; i < pages; i++) {
    const page = pdfDoc.addPage([png.width, png.height]);
    page.drawImage(png, {
      x: 0,
      y: 0,
      width: png.width,
      height: png.height,
    });
  }
  return Buffer.from(await pdfDoc.save());
}

/** Image + white rectangle + "999" text drawn over it (content stream). */
async function embedPngWithDrawnOverlay(pngBytes: Buffer): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const png = await pdfDoc.embedPng(pngBytes);
  const page = pdfDoc.addPage([png.width, png.height]);
  page.drawImage(png, {
    x: 0,
    y: 0,
    width: png.width,
    height: png.height,
  });
  page.drawRectangle({
    x: 10,
    y: 10,
    width: 28,
    height: 20,
    color: rgb(1, 1, 1),
  });
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  page.drawText("999", {
    x: 12,
    y: 14,
    size: 12,
    font,
    color: rgb(0, 0, 0),
  });
  return Buffer.from(await pdfDoc.save());
}

async function embedPngWithSquareAnnotation(pngBytes: Buffer): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const png = await pdfDoc.embedPng(pngBytes);
  const page = pdfDoc.addPage([png.width, png.height]);
  page.drawImage(png, {
    x: 0,
    y: 0,
    width: png.width,
    height: png.height,
  });
  const annot = pdfDoc.context.obj({
    Type: "Annot",
    Subtype: "Square",
    Rect: [10, 10, 40, 40],
    IC: [1, 1, 1],
    C: [1, 0, 0],
    F: 4,
  });
  page.node.addAnnot(pdfDoc.context.register(annot));
  return Buffer.from(await pdfDoc.save());
}

async function embedPngWithFreeTextAnnotation(pngBytes: Buffer): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const png = await pdfDoc.embedPng(pngBytes);
  const page = pdfDoc.addPage([png.width, png.height]);
  page.drawImage(png, {
    x: 0,
    y: 0,
    width: png.width,
    height: png.height,
  });
  const annot = pdfDoc.context.obj({
    Type: "Annot",
    Subtype: "FreeText",
    Rect: [8, 20, 55, 42],
    Contents: PDFString.of("999"),
    F: 4,
    DA: PDFString.of("/Helv 12 Tf 0 0 0 rg"),
  });
  page.node.addAnnot(pdfDoc.context.register(annot));
  return Buffer.from(await pdfDoc.save());
}

/** Image on A4 with margins; optional footer text below the image. */
async function embedPngOnA4(
  pngBytes: Buffer,
  opts?: { footerOutside?: boolean },
): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  const png = await pdfDoc.embedPng(pngBytes);
  const page = pdfDoc.addPage([595, 842]);
  const drawW = 300;
  const drawH = (png.height / png.width) * drawW;
  const x = 100;
  const y = 400;
  page.drawImage(png, { x, y, width: drawW, height: drawH });
  if (opts?.footerOutside) {
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    page.drawText("Certified copy — footer", {
      x: 100,
      y: 40,
      size: 10,
      font,
      color: rgb(0.2, 0.2, 0.2),
    });
  }
  return Buffer.from(await pdfDoc.save());
}

describe("image cert verified via PDF upload", () => {
  beforeEach(async () => {
    await prisma.verificationLog.deleteMany();
    await prisma.certificate.deleteMany();
    await prisma.logEntry.deleteMany();
    await prisma.logHead.deleteMany();
    await prisma.checkpoint.deleteMany();
    await prisma.publicKeyRecord.deleteMany();
  });

  it("PNG embedded in single-page PDF → MODIFIED_REENCODED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "photo.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngInPdf(originalPng, 1);

    expect(createHash("sha256").update(pdf).digest("hex")).not.toBe(
      certified.sha256,
    );

    const result = await verifyUpload(
      makeFile(pdf, "photo.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("MODIFIED_REENCODED");
    expect(
      result.analysis?.checks.some(
        (c) =>
          c.name === "format-conversion" &&
          c.status === "PASSED" &&
          /Uploaded as PDF/i.test(c.detail ?? ""),
      ),
    ).toBe(true);
    expect(
      result.analysis?.checks.some((c) => c.name === "pdf-overlay"),
    ).toBeFalsy();
    expect(result.explanation?.disclaimer).toMatch(/re-saved/i);
    expect(result.explanation?.disclaimer).not.toMatch(
      /unchanged since it was certified/i,
    );
  });

  it("drawRectangle/drawText over the image → TAMPERED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "over.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngWithDrawnOverlay(originalPng);

    const result = await verifyUpload(
      makeFile(pdf, "over.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("TAMPERED");
    expect(result.imageAnalysis?.reason).toMatch(/drawn over the image/i);
    expect(
      result.analysis?.checks.some(
        (c) => c.name === "pdf-overlay" && c.status === "FAILED",
      ),
    ).toBe(true);
    expect(result.explanation?.disclaimer ?? "").not.toMatch(/unchanged/i);
  });

  it("white Square annotation over the image → TAMPERED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "sq.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngWithSquareAnnotation(originalPng);

    const result = await verifyUpload(
      makeFile(pdf, "sq.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("TAMPERED");
    expect(
      result.analysis?.checks.some(
        (c) => c.name === "pdf-overlay" && c.status === "FAILED",
      ),
    ).toBe(true);
  });

  it("FreeText annotation over the image → TAMPERED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "ft.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngWithFreeTextAnnotation(originalPng);

    const result = await verifyUpload(
      makeFile(pdf, "ft.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("TAMPERED");
    expect(
      result.analysis?.checks.some(
        (c) => c.name === "pdf-overlay" && c.status === "FAILED",
      ),
    ).toBe(true);
  });

  it("footer text outside the image area → not TAMPERED (note only)", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "foot.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngOnA4(originalPng, { footerOutside: true });

    const result = await verifyUpload(
      makeFile(pdf, "foot.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("MODIFIED_REENCODED");
    expect(
      result.analysis?.checks.some((c) => c.name === "pdf-overlay"),
    ).toBeFalsy();
    expect(
      result.analysis?.checks.find((c) => c.name === "format-conversion")
        ?.detail,
    ).toMatch(/outside the image area/i);
  });

  it("image scaled onto A4 with margins → MODIFIED_REENCODED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "a4.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngOnA4(originalPng);

    const result = await verifyUpload(
      makeFile(pdf, "a4.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("MODIFIED_REENCODED");
  });

  it("painted region then embedded in PDF → TAMPERED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "scene.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pixels = await decodeImage(originalPng);
    const edited = await paintRect(pixels, 10, 10, 20, 20, [255, 0, 0]);
    const editedPng = await sharp(Buffer.from(edited.data), {
      raw: {
        width: edited.width,
        height: edited.height,
        channels: 4,
      },
    })
      .png()
      .toBuffer();
    const pdf = await embedPngInPdf(editedPng, 1);

    const result = await verifyUpload(
      makeFile(pdf, "scene.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("TAMPERED");
    expect(result.explanation?.disclaimer ?? "").not.toMatch(/unchanged/i);
  });

  it("two-page PDF → ANALYSIS_UNAVAILABLE with clear message", async () => {
    const buf = await texturedImage(96, 96);
    const certified = await certifyUpload(makeFile(buf, "multi.png"));
    const originalPng = await loadCertifiedPng(certified.certId);
    const pdf = await embedPngInPdf(originalPng, 2);

    const result = await verifyUpload(
      makeFile(pdf, "multi.pdf", "application/pdf"),
      certified.certId,
    );
    expect(result.result).toBe("ANALYSIS_UNAVAILABLE");
    expect(result.message).toBe(PDF_IMAGE_UNAVAILABLE_MESSAGE);
    expect(result.explanation?.disclaimer).toBe("");
  });
});

describe("binary / image dimension parsing", () => {
  it("never reports dimensions for a PDF buffer", () => {
    const pdf = Buffer.from("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n");
    expect(readImageDimensions(pdf)).toBeUndefined();
    expect(readImageDimensions(pdf, "image/png")).toBeUndefined();
  });

  it("reads real PNG dimensions and rejects absurd sizes", async () => {
    const png = await texturedImage(64, 48);
    expect(readImageDimensions(png)).toEqual({ width: 64, height: 48 });

    // Corrupt IHDR width to an absurd value — must not report it
    const bad = Buffer.from(png);
    bad.writeUInt32BE(200_000, 16);
    expect(readImageDimensions(bad)).toBeUndefined();
  });

  it("summarises PNG → PDF without listing chunks or fake dims", async () => {
    const png = await texturedImage(32, 32);
    const pdf = await embedPngInPdf(png, 1);
    const diff = diffImage(png, pdf, "image/png");
    expect(diff.summary).toMatch(/completely different \(PNG → PDF\)/i);
    expect(diff.changes).toEqual([]);
    expect(diff.imageMeta?.uploaded).toBeUndefined();
  });

  it("summarises when more than half of chunks differ", () => {
    const a = Buffer.alloc(CHUNKY, 1);
    const b = Buffer.alloc(CHUNKY, 2);
    const diff = diffBinary(a, b);
    expect(diff.summary).toMatch(/completely different/i);
    expect(diff.changes).toEqual([]);
  });
});

/** Enough bytes for >1 chunk at 4 KB. */
const CHUNKY = 4096 * 4;
