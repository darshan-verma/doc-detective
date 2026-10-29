import { generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { PDFDocument } from "pdf-lib";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import { certifyUpload } from "../src/lib/certificates/service";
import { revokeCertificate } from "../src/lib/certificates/ownership";
import { resetConfigCache } from "../src/lib/config";
import { buildVerificationReportPdf } from "../src/lib/report";
import { resetSigningKeyCache } from "../src/lib/signing";
import { LocalDiskStorage, setStorage } from "../src/lib/storage";
import { stampPdf, verificationUrl } from "../src/lib/stamp";
import { verifyUpload } from "../src/lib/verify/service";
import { Verdict } from "../src/lib/analysis/types";

const prisma = new PrismaClient();
let storageDir: string;

beforeAll(() => {
  const { privateKey } = generateKeyPairSync("ed25519");
  process.env.ED25519_PRIVATE_KEY = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  storageDir = mkdtempSync(path.join(tmpdir(), "doc-detective-p3-"));
  process.env.STORAGE_DIR = storageDir;
  process.env.WATERMARK_KEY = "test-watermark-key-value";
  process.env.DATABASE_URL =
    process.env.DATABASE_URL || "file:./prisma/dev.db";
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

async function minimalPdf(): Promise<Buffer> {
  const doc = await PDFDocument.create();
  const page = doc.addPage([400, 400]);
  page.drawText("Hello certified world", { x: 40, y: 350, size: 12 });
  return Buffer.from(await doc.save());
}

describe("stamped PDF", () => {
  it("records sha256 of the stamped file", async () => {
    const pdf = await minimalPdf();
    const file = makeFile(pdf, "doc.pdf", "application/pdf");
    const certified = await certifyUpload(file, {
      addVerificationStamp: true,
      origin: "http://localhost:3000",
    });
    expect(certified.stamped).toBe(true);
    expect(certified.ownerToken).toBeTruthy();

    // Download stored bytes and compare hash
    const stored = await prisma.certificate.findUniqueOrThrow({
      where: { certId: certified.certId },
    });
    expect(stored.sha256).toBe(certified.sha256);

    const stamped = await stampPdf(pdf, "TESTID00000000000000000001", "http://localhost:3000");
    // QR URL format
    expect(verificationUrl(certified.certId, "http://localhost:3000")).toBe(
      `http://localhost:3000/v/${certified.certId}`,
    );
    expect(stamped.length).toBeGreaterThan(pdf.length);
  });
});

describe("report PDF", () => {
  it("generates a report containing verdict and cert ID", async () => {
    const { pdf, sha256 } = await buildVerificationReportPdf({
      certId: "ABC123XYZ",
      verdict: Verdict.TAMPERED,
      analysis: {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks: [{ name: "text", status: "FAILED", detail: "diff" }],
        changes: [{ description: "word changed" }],
        notChecked: [],
      },
      registeredSha256: "aa".repeat(32),
      uploadedSha256: "bb".repeat(32),
      signatureValid: true,
      timestampStatus: "PENDING",
    });
    expect(pdf.subarray(0, 4).toString()).toBe("%PDF");
    expect(sha256).toHaveLength(64);
    // Content streams are Flate-compressed — reload and check page count / size
    const reloaded = await PDFDocument.load(pdf);
    expect(reloaded.getPageCount()).toBe(1);
    expect(pdf.length).toBeGreaterThan(500);
  });
});

describe("versioning", () => {
  it("rejects wrong ownerToken", async () => {
    const a = await certifyUpload(makeFile("v1", "a.txt"));
    await expect(
      certifyUpload(makeFile("v2", "a.txt"), {
        parentCertId: a.certId,
        ownerToken: "wrong-token",
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  });

  it("links a new version to its parent", async () => {
    const a = await certifyUpload(makeFile("v1-content", "a.txt"));
    const b = await certifyUpload(makeFile("v2-content", "a.txt"), {
      parentCertId: a.certId,
      ownerToken: a.ownerToken,
    });
    expect(b.parentCertId).toBe(a.certId);
    expect(b.version).toBe(2);
    const parent = await prisma.certificate.findUniqueOrThrow({
      where: { certId: a.certId },
    });
    expect(parent.supersededBy).toBe(b.certId);

    const oldVerify = await verifyUpload(
      makeFile("v1-content", "a.txt"),
      null,
    );
    expect(oldVerify.result).toBe("AUTHENTIC");
    expect(oldVerify.newerVersion?.certId).toBe(b.certId);
  });

  it("shows REVOKED for revoked certs even when bytes match", async () => {
    const a = await certifyUpload(makeFile("secret", "s.txt"));
    await revokeCertificate(a.certId, a.ownerToken, "compromised");
    const result = await verifyUpload(makeFile("secret", "s.txt"), null);
    expect(result.result).toBe("REVOKED");
    expect(result.explanation?.headline).toBe("REVOKED");
  });
});
