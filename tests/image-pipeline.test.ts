import { createHash, generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import sharp from "sharp";
import { resetConfigCache } from "../src/lib/config";
import { LocalDiskStorage, setStorage } from "../src/lib/storage";
import { certifyUpload } from "../src/lib/certificates/service";
import { verifyUpload } from "../src/lib/verify/service";
import {
  cellSignatures,
  compareCells,
  decodeImage,
  embedCertId,
  encodeJpeg,
  extract,
  hamming,
  phash64,
} from "../src/lib/image";
import { resetSigningKeyCache } from "../src/lib/signing";
import type { PixelBuffer } from "../src/lib/image/pixels";

const prisma = new PrismaClient();
let storageDir: string;
let privatePem: string;

const WATERMARK_KEY = "test-watermark-key-value";

beforeAll(() => {
  const { privateKey } = generateKeyPairSync("ed25519");
  privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  storageDir = mkdtempSync(path.join(tmpdir(), "doc-detective-img-"));
  process.env.ED25519_PRIVATE_KEY = privatePem;
  process.env.WATERMARK_KEY = WATERMARK_KEY;
  process.env.MAX_UPLOAD_MB = "25";
  process.env.STORAGE_DIR = storageDir;
  process.env.DATABASE_URL =
    process.env.DATABASE_URL || "file:./prisma/dev.db";
  process.env.TAMPER_SCORE_ALERT = "1.5";
  process.env.IMAGE_GRID_SIZE = "8"; // smaller grid for faster tests
  resetConfigCache();
  resetSigningKeyCache();
  setStorage(new LocalDiskStorage(storageDir));
});

beforeEach(async () => {
  await prisma.verificationLog.deleteMany();
  await prisma.certificate.deleteMany();
  await prisma.logEntry.deleteMany();
  await prisma.checkpoint.deleteMany();
  await prisma.publicKeyRecord.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
  rmSync(storageDir, { recursive: true, force: true });
  setStorage(null);
  resetConfigCache();
  resetSigningKeyCache();
});

/** Gradient + noise so phash/watermark have structure. */
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

describe("watermark", () => {
  it("embed then extract returns the same payload with confidence > 0.9", async () => {
    const buf = await texturedImage(160, 160);
    const pixels = await decodeImage(buf);
    const { pixels: marked } = embedCertId(pixels, "AB12CD", {
      key: WATERMARK_KEY,
      step: 24,
    });
    const result = extract(marked, { key: WATERMARK_KEY, step: 24 });
    expect(result.payload).toBe("AB12CD");
    expect(result.confidence).toBeGreaterThan(0.9);
  });

  it("survives JPEG quality 85 re-encode with payload intact", async () => {
    const buf = await texturedImage(192, 192);
    const pixels = await decodeImage(buf);
    const { pixels: marked } = embedCertId(pixels, "XY99ZZ", {
      key: WATERMARK_KEY,
      step: 24,
    });
    const jpeg = await encodeJpeg(marked, 85);
    const decoded = await decodeImage(jpeg);
    const result = extract(decoded, { key: WATERMARK_KEY, step: 24 });
    expect(result.payload).toBe("XY99ZZ");
    expect(result.confidence).toBeGreaterThan(0.55);
  });
});

describe("phash", () => {
  it("re-encoded copy has Hamming distance under 6", async () => {
    const buf = await texturedImage(96, 96);
    const pixels = await decodeImage(buf);
    const a = phash64(pixels);
    const jpeg = await encodeJpeg(pixels, 90);
    const redecoded = await decodeImage(jpeg);
    const b = phash64(redecoded);
    expect(hamming(a, b)).toBeLessThan(6);
  });
});

describe("cell signatures", () => {
  it("editing one small region flags only cells covering it", async () => {
    const buf = await texturedImage(128, 128);
    const pixels = await decodeImage(buf);
    const gridSize = 8;
    const orig = cellSignatures(pixels, gridSize);
    // Paint a small square in the top-left
    const edited = await paintRect(pixels, 2, 2, 12, 12, [255, 0, 0]);
    const next = cellSignatures(edited, gridSize);
    const cmp = compareCells(orig, next, gridSize, {
      hammingThreshold: 8,
      lumaDeltaThreshold: 10,
    });
    expect(cmp.changedCells.length).toBeGreaterThan(0);
    expect(cmp.changedCells.length).toBeLessThan(gridSize * gridSize * 0.25);
    for (const c of cmp.changedCells) {
      expect(c.x).toBeLessThan(3);
      expect(c.y).toBeLessThan(3);
    }
  });
});

describe("image certify/verify flows", () => {
  it("identical pixels re-saved → MODIFIED_REENCODED", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "photo.png"));
    // Re-encode certified PNG (lossless) after decode — same pixels, new bytes
    // Download path stores watermarked PNG; re-saving via sharp changes compression
    // but not pixels → sha differs, cells match → MODIFIED_REENCODED
    const stored = await prisma.certificate.findUniqueOrThrow({
      where: { certId: certified.certId },
    });
    const storage = new LocalDiskStorage(storageDir);
    const stream = await storage.get(stored.storagePath);
    const chunks: Buffer[] = [];
    for await (const c of stream) {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    const originalPng = Buffer.concat(chunks);
    const pixels = await decodeImage(originalPng);
    // Re-save with different PNG compression → different SHA, identical pixels
    const resaved = await sharp(Buffer.from(pixels.data), {
      raw: {
        width: pixels.width,
        height: pixels.height,
        channels: 4,
      },
    })
      .png({ compressionLevel: 1 })
      .toBuffer();

    expect(createHash("sha256").update(resaved).digest("hex")).not.toBe(
      certified.sha256,
    );

    const result = await verifyUpload(makeFile(resaved, "photo.png"), null);
    expect(result.result).toBe("MODIFIED_REENCODED");
    expect(result.imageAnalysis?.changedPercent).toBe(0);
  });

  it("cropped upload → dimensions differ with no cell comparison", async () => {
    const buf = await texturedImage(128, 128);
    const certified = await certifyUpload(makeFile(buf, "scene.png"));
    const cropped = await sharp(buf).extract({ left: 0, top: 0, width: 96, height: 64 }).png().toBuffer();
    const result = await verifyUpload(
      makeFile(cropped, `scene_doc-detective_${certified.certId}.png`),
      certified.certId,
    );
    expect(result.result).toBe("TAMPERED");
    expect(result.imageAnalysis?.reason).toBe("dimensions differ");
    expect(result.imageAnalysis?.changedCells).toEqual([]);
  });

  it("tampered record signature → signatureValid false", async () => {
    const buf = await texturedImage(96, 96);
    const certified = await certifyUpload(makeFile(buf, "sig.png"));
    await prisma.certificate.update({
      where: { certId: certified.certId },
      data: { signature: Buffer.alloc(64, 1).toString("base64") },
    });

    // Exact hash match path
    const storage = new LocalDiskStorage(storageDir);
    const cert = await prisma.certificate.findUniqueOrThrow({
      where: { certId: certified.certId },
    });
    const stream = await storage.get(cert.storagePath);
    const chunks: Buffer[] = [];
    for await (const c of stream) {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    const bytes = Buffer.concat(chunks);
    const result = await verifyUpload(makeFile(bytes, "sig.png"), null);
    expect(result.result).toBe("TAMPERED");
    expect(result.signatureValid).toBe(false);
  });

  it("AUTHENTIC for exact certified PNG bytes", async () => {
    const buf = await texturedImage(80, 80);
    const certified = await certifyUpload(makeFile(buf, "exact.png"));
    const storage = new LocalDiskStorage(storageDir);
    const cert = await prisma.certificate.findUniqueOrThrow({
      where: { certId: certified.certId },
    });
    const stream = await storage.get(cert.storagePath);
    const chunks: Buffer[] = [];
    for await (const c of stream) {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    const bytes = Buffer.concat(chunks);
    const result = await verifyUpload(makeFile(bytes, "exact.png"), null);
    expect(result.result).toBe("AUTHENTIC");
    expect(result.signatureValid).toBe(true);
  });
});
