import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import QRCode from "qrcode";
import sharp from "sharp";

export function verificationUrl(certId: string, origin?: string): string {
  const base = origin ?? process.env.APP_ORIGIN ?? "http://localhost:3000";
  return `${base.replace(/\/$/, "")}/v/${certId}`;
}

/** Render QR as PNG buffer. */
export async function qrPng(url: string, size = 128): Promise<Buffer> {
  return QRCode.toBuffer(url, {
    type: "png",
    width: size,
    margin: 1,
    errorCorrectionLevel: "M",
  });
}

/**
 * Stamp a QR + cert ID onto the last page of a PDF (footer/margin).
 * IMPORTANT: call this BEFORE hashing — the stamped file is what gets certified.
 */
export async function stampPdf(
  pdfBytes: Buffer,
  certId: string,
  origin?: string,
): Promise<Buffer> {
  const url = verificationUrl(certId, origin);
  const qr = await qrPng(url, 96);
  const doc = await PDFDocument.load(pdfBytes);
  const pages = doc.getPages();
  const page = pages[pages.length - 1]!;
  const qrImage = await doc.embedPng(qr);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const margin = 24;
  const qrSize = 48;
  page.drawImage(qrImage, {
    x: margin,
    y: margin,
    width: qrSize,
    height: qrSize,
  });
  page.drawText(`doc-detective ${certId}`, {
    x: margin + qrSize + 8,
    y: margin + 16,
    size: 8,
    font,
    color: rgb(0.2, 0.2, 0.2),
  });
  page.drawText(url, {
    x: margin + qrSize + 8,
    y: margin + 6,
    size: 6,
    font,
    color: rgb(0.4, 0.4, 0.4),
  });
  const out = await doc.save();
  return Buffer.from(out);
}

/** Composite a QR into the bottom-right corner of an image (PNG out). */
export async function stampImage(
  imageBytes: Buffer,
  certId: string,
  origin?: string,
): Promise<Buffer> {
  const url = verificationUrl(certId, origin);
  const meta = await sharp(imageBytes).metadata();
  const w = meta.width ?? 512;
  const h = meta.height ?? 512;
  const qrSize = Math.max(48, Math.min(96, Math.floor(w * 0.12)));
  const qr = await qrPng(url, qrSize * 2);
  const left = w - qrSize - 8;
  const top = h - qrSize - 8;
  return sharp(imageBytes)
    .composite([{ input: await sharp(qr).resize(qrSize, qrSize).png().toBuffer(), left, top }])
    .png()
    .toBuffer();
}
