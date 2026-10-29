/**
 * Identify + certify recognition tests.
 *
 * Filename-only policy: a fake `_doc-detective_<realCertId>` suffix with
 * unrelated content returns LIKELY_MODIFIED_COPY with filenameOnly=true.
 * POST certify does NOT block on filename-only (weak) signals — it proceeds
 * as a new certificate. Documented and asserted below.
 */
import { generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import { PDFDocument } from "pdf-lib";
import sharp from "sharp";
import { certifyUpload } from "../src/lib/certificates/service";
import { revokeCertificate } from "../src/lib/certificates/ownership";
import { resetConfigCache } from "../src/lib/config";
import { AppError } from "../src/lib/errors";
import { certifiedFilename } from "../src/lib/filenames";
import { identifyFile, isStrongCandidate } from "../src/lib/identify";
import { decodeImage, encodePng } from "../src/lib/image";
import type { PixelBuffer } from "../src/lib/image/pixels";
import { resetSigningKeyCache } from "../src/lib/signing";
import { getStorage, LocalDiskStorage, setStorage } from "../src/lib/storage";
import { verifyLogChain } from "../src/lib/trust/log";

const prisma = new PrismaClient();
let storageDir: string;

beforeAll(() => {
  const { privateKey } = generateKeyPairSync("ed25519");
  process.env.ED25519_PRIVATE_KEY = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  storageDir = mkdtempSync(path.join(tmpdir(), "doc-detective-id-"));
  process.env.STORAGE_DIR = storageDir;
  process.env.WATERMARK_KEY = "test-watermark-key-value";
  process.env.DATABASE_URL =
    process.env.DATABASE_URL || "file:./prisma/dev.db";
  process.env.IMAGE_GRID_SIZE = "8";
  resetConfigCache();
  resetSigningKeyCache();
  setStorage(new LocalDiskStorage(storageDir));
});

beforeEach(async () => {
  await prisma.verificationLog.deleteMany();
  await prisma.certificate.deleteMany();
  await prisma.logEntry.deleteMany();
  await prisma.logHead.deleteMany();
  await prisma.checkpoint.deleteMany();
  await prisma.publicKeyRecord.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
  rmSync(storageDir, { recursive: true, force: true });
  setStorage(null);
});

function makeFile(content: string | Buffer, name: string, type = "text/plain") {
  const buf = typeof content === "string" ? Buffer.from(content) : content;
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  return new File([ab as ArrayBuffer], name, { type });
}

const LONG_DOC = `
The quick brown fox jumps over the lazy dog. This document establishes
the terms of service for the certified platform. Users agree to hash
fingerprints, transparency logs, and watermark protection. Additional
clauses cover liability, jurisdiction, and data retention policies.
Paragraph two continues with more boilerplate about integrity verification
and chain of custody for digital evidence submissions worldwide.
`;

async function pdfWithText(text: string): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([500, 700]);
  const lines = text.trim().split("\n");
  let y = 650;
  for (const line of lines) {
    page.drawText(line.trim().slice(0, 80), { x: 40, y, size: 10 });
    y -= 14;
  }
  return Buffer.from(await doc.save());
}

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

function paintRect(
  pixels: PixelBuffer,
  x0: number,
  y0: number,
  w: number,
  h: number,
  rgb: [number, number, number],
): PixelBuffer {
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

describe("identify + certify recognition", () => {
  it("second certify of same bytes returns ALREADY_CERTIFIED; count unchanged", async () => {
    const file = makeFile("identical-bytes-payload", "a.txt");
    const first = await certifyUpload(file);
    expect(first.status).toBe("CREATED");
    const count1 = await prisma.certificate.count();
    const log1 = await prisma.logEntry.count();

    const second = await certifyUpload(makeFile("identical-bytes-payload", "a.txt"));
    expect(second.status).toBe("ALREADY_CERTIFIED");
    if (second.status === "ALREADY_CERTIFIED") {
      expect(second.matchedOn).toMatch(/sha256|inputSha256/);
      expect(second.certificate.certId).toBe(
        first.status === "CREATED" ? first.certId : "",
      );
    }
    expect(await prisma.certificate.count()).toBe(count1);
    expect(await prisma.logEntry.count()).toBe(log1);
  });

  it("recognizes original via inputSha256 and stamped download via sha256", async () => {
    const pdf = await pdfWithText(LONG_DOC);
    const original = makeFile(pdf, "doc.pdf", "application/pdf");
    const certified = await certifyUpload(original, {
      addVerificationStamp: true,
      origin: "http://localhost:3000",
    });
    expect(certified.status).toBe("CREATED");
    if (certified.status !== "CREATED") return;

    const row = await prisma.certificate.findUniqueOrThrow({
      where: { certId: certified.certId },
    });
    expect(row.inputSha256).toBeTruthy();
    expect(row.inputSha256).not.toBe(row.sha256);

    const reOrig = await certifyUpload(
      makeFile(pdf, "doc.pdf", "application/pdf"),
    );
    expect(reOrig.status).toBe("ALREADY_CERTIFIED");
    if (reOrig.status === "ALREADY_CERTIFIED") {
      expect(reOrig.matchedOn).toBe("inputSha256");
    }

    const storage = getStorage();
    const stream = await storage.get(row.storagePath);
    const chunks: Buffer[] = [];
    for await (const c of stream) {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    const stampedBytes = Buffer.concat(chunks);
    const reStamped = await certifyUpload(
      makeFile(stampedBytes, "doc.pdf", "application/pdf"),
    );
    expect(reStamped.status).toBe("ALREADY_CERTIFIED");
    if (reStamped.status === "ALREADY_CERTIFIED") {
      expect(reStamped.matchedOn).toBe("sha256");
    }
  });

  it("renamed copy (suffix removed) is still EXACT", async () => {
    const first = await certifyUpload(makeFile("rename-me", "report.txt"));
    expect(first.status).toBe("CREATED");
    if (first.status !== "CREATED") return;

    const identified = await identifyFile(
      makeFile("rename-me", "totally-different-name.txt"),
    );
    expect(identified.kind).toBe("EXACT");
  });

  it("edited PDF (one word) -> SIMILAR with text_simhash signal", async () => {
    const pdfA = await pdfWithText(LONG_DOC);
    const created = await certifyUpload(
      makeFile(pdfA, "contract.pdf", "application/pdf"),
    );
    expect(created.status).toBe("CREATED");

    const pdfB = await pdfWithText(LONG_DOC.replace("lazy dog", "lazy cat"));
    const id = await identifyFile(
      makeFile(pdfB, "contract.pdf", "application/pdf"),
    );
    expect(id.kind).toBe("LIKELY_MODIFIED_COPY");
    if (id.kind !== "LIKELY_MODIFIED_COPY") return;
    expect(id.candidates.some((c) => c.signals.some((s) => s.type === "text_simhash"))).toBe(
      true,
    );

    await expect(
      certifyUpload(makeFile(pdfB, "contract.pdf", "application/pdf")),
    ).rejects.toMatchObject({ code: "SIMILAR_CERTIFICATE_EXISTS" });
  });

  it("edited image with watermark intact -> SIMILAR with watermark", async () => {
    const buf = await texturedImage();
    const created = await certifyUpload(makeFile(buf, "photo.png"));
    expect(created.status).toBe("CREATED");
    if (created.status !== "CREATED") return;

    const row = await prisma.certificate.findUniqueOrThrow({
      where: { certId: created.certId },
    });
    const storage = getStorage();
    const stream = await storage.get(row.storagePath);
    const chunks: Buffer[] = [];
    for await (const c of stream) {
      chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    const certifiedPng = Buffer.concat(chunks);
    const pixels = await decodeImage(certifiedPng);
    const edited = paintRect(pixels, 10, 10, 20, 20, [255, 0, 0]);
    const editedBytes = await encodePng(edited);

    const id = await identifyFile(makeFile(editedBytes, "photo.png"));
    expect(id.kind).toBe("LIKELY_MODIFIED_COPY");
    if (id.kind !== "LIKELY_MODIFIED_COPY") return;
    expect(
      id.candidates.some((c) => c.signals.some((s) => s.type === "watermark")),
    ).toBe(true);
  });

  it("unrelated file -> NEW", async () => {
    await certifyUpload(makeFile("alpha content here", "a.txt"));
    const id = await identifyFile(makeFile("totally other stuff zzz", "b.txt"));
    expect(id.kind).toBe("NEW");
  });

  it("fake suffix only is weak / non-blocking (filenameOnly)", async () => {
    const real = await certifyUpload(makeFile("real-payload-aaa", "real.txt"));
    expect(real.status).toBe("CREATED");
    if (real.status !== "CREATED") return;

    const fakeName = certifiedFilename("unrelated.txt", real.certId);
    const id = await identifyFile(
      makeFile("completely-different-content-xyz", fakeName),
    );
    expect(id.kind).toBe("LIKELY_MODIFIED_COPY");
    if (id.kind !== "LIKELY_MODIFIED_COPY") return;
    expect(id.candidates[0]!.filenameOnly).toBe(true);
    expect(isStrongCandidate(id.candidates[0]!)).toBe(false);

    // Certify proceeds (does not auto-block on filename-only)
    const created = await certifyUpload(
      makeFile("completely-different-content-xyz", fakeName),
    );
    expect(created.status).toBe("CREATED");
    expect(await prisma.certificate.count()).toBe(2);
  });

  it("force=true creates certificate with similarToCertId and both pages link", async () => {
    const pdfA = await pdfWithText(LONG_DOC);
    const a = await certifyUpload(
      makeFile(pdfA, "a.pdf", "application/pdf"),
    );
    expect(a.status).toBe("CREATED");
    if (a.status !== "CREATED") return;

    const pdfB = await pdfWithText(LONG_DOC.replace("lazy dog", "lazy cat"));
    const b = await certifyUpload(
      makeFile(pdfB, "b.pdf", "application/pdf"),
      { force: true },
    );
    expect(b.status).toBe("CREATED");
    if (b.status !== "CREATED") return;
    expect(b.similarToCertId).toBe(a.certId);

    const rowB = await prisma.certificate.findUniqueOrThrow({
      where: { certId: b.certId },
    });
    expect(rowB.similarToCertId).toBe(a.certId);

    const later = await prisma.certificate.findMany({
      where: { similarToCertId: a.certId },
    });
    expect(later.map((c) => c.certId)).toContain(b.certId);

    const log = await prisma.logEntry.findFirst({
      where: { certId: b.certId, eventType: "CERTIFICATE_CREATED" },
    });
    expect(log?.details).toContain(a.certId);
  });

  it("two concurrent certify requests for identical bytes produce one certificate", async () => {
    const payload = "concurrent-identical-" + Date.now();
    const results = await Promise.all([
      certifyUpload(makeFile(payload, "c1.txt")),
      certifyUpload(makeFile(payload, "c2.txt")),
    ]);
    const created = results.filter((r) => r.status === "CREATED");
    const already = results.filter((r) => r.status === "ALREADY_CERTIFIED");
    expect(created.length + already.length).toBe(2);
    expect(created.length).toBe(1);
    expect(already.length).toBe(1);
    expect(await prisma.certificate.count()).toBe(1);
  });

  it(
    "20 concurrent certifies of different files all succeed with contiguous log seqs",
    async () => {
      const stamp = Date.now();
      const results = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          certifyUpload(makeFile(`concurrent-diff-${stamp}-${i}`, `d${i}.txt`)),
        ),
      );
      expect(results.every((r) => r.status === "CREATED")).toBe(true);
      expect(await prisma.certificate.count()).toBe(20);

      const entries = await prisma.logEntry.findMany({ orderBy: { seq: "asc" } });
      expect(entries.map((e) => e.seq)).toEqual(
        Array.from({ length: 20 }, (_, i) => i + 1),
      );
      const seqs = entries.map((e) => e.seq);
      expect(new Set(seqs).size).toBe(20);

      const chain = await verifyLogChain();
      expect(chain.ok).toBe(true);
    },
    60_000,
  );

  it("revoked match returns ALREADY_CERTIFIED_REVOKED and creates nothing", async () => {
    const a = await certifyUpload(makeFile("to-revoke", "r.txt"));
    expect(a.status).toBe("CREATED");
    if (a.status !== "CREATED") return;
    await revokeCertificate(a.certId, a.ownerToken, "test revoke");

    const again = await certifyUpload(makeFile("to-revoke", "r.txt"));
    expect(again.status).toBe("ALREADY_CERTIFIED_REVOKED");
    expect(await prisma.certificate.count()).toBe(1);
  });

  it("valid parentCertId + ownerToken bypasses similarity for that parent", async () => {
    const pdfA = await pdfWithText(LONG_DOC);
    const a = await certifyUpload(
      makeFile(pdfA, "v1.pdf", "application/pdf"),
    );
    expect(a.status).toBe("CREATED");
    if (a.status !== "CREATED") return;

    const pdfB = await pdfWithText(LONG_DOC.replace("lazy dog", "lazy cat"));

    await expect(
      certifyUpload(makeFile(pdfB, "v2.pdf", "application/pdf"), {
        parentCertId: a.certId,
        ownerToken: "wrong-token",
      }),
    ).rejects.toBeInstanceOf(AppError);

    const v2 = await certifyUpload(
      makeFile(pdfB, "v2.pdf", "application/pdf"),
      {
        parentCertId: a.certId,
        ownerToken: a.ownerToken,
      },
    );
    expect(v2.status).toBe("CREATED");
    if (v2.status === "CREATED") {
      expect(v2.parentCertId).toBe(a.certId);
      expect(v2.version).toBe(2);
    }
  });
});
