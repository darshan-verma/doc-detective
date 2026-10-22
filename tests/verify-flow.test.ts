import { generateKeyPairSync } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import path from "path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import { resetConfigCache } from "../src/lib/config";
import { LocalDiskStorage, setStorage } from "../src/lib/storage";
import { certifyUpload } from "../src/lib/certificates/service";
import { verifyUpload } from "../src/lib/verify/service";
import { resetSigningKeyCache } from "../src/lib/signing";

const prisma = new PrismaClient();
let storageDir: string;

beforeAll(() => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  storageDir = mkdtempSync(path.join(tmpdir(), "doc-detective-"));
  process.env.ED25519_PRIVATE_KEY = privatePem;
  process.env.WATERMARK_KEY = "test-watermark-key-value";
  process.env.MAX_UPLOAD_MB = "25";
  process.env.STORAGE_DIR = storageDir;
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

function makeFile(content: string | Buffer, name: string, type = "text/plain") {
  const buf = typeof content === "string" ? Buffer.from(content) : content;
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  return new File([ab as ArrayBuffer], name, { type });
}

describe("verify flows", () => {
  it("returns AUTHENTIC for unchanged content", async () => {
    const file = makeFile("hello world", "note.txt");
    const certified = await certifyUpload(file);
    const result = await verifyUpload(
      makeFile("hello world", "renamed.txt"),
      null,
    );
    expect(result.result).toBe("AUTHENTIC");
    expect(result.certId).toBe(certified.certId);
    expect(result.uploadedSha256).toBe(certified.sha256);
  });

  it("returns TAMPERED when content changes and certId is known", async () => {
    const original = makeFile("line one\nline two\n", "doc.txt");
    const certified = await certifyUpload(original);
    const tampered = makeFile("line one\nline CHANGED\n", "doc.txt");
    const result = await verifyUpload(tampered, certified.certId);
    expect(result.result).toBe("TAMPERED");
    expect(result.diff).toBeDefined();
    expect(result.diff!.type).toBe("text");
  });

  it("returns TAMPERED when certId is parsed from certified filename", async () => {
    const original = makeFile("alpha", "report.txt");
    const certified = await certifyUpload(original);
    const tampered = makeFile(
      "beta",
      `report_doc-detective_${certified.certId}.txt`,
    );
    const result = await verifyUpload(tampered, null);
    expect(result.result).toBe("TAMPERED");
    expect(result.certId).toBe(certified.certId);
  });

  it("returns NOT_FOUND when hash unknown and no certId", async () => {
    const result = await verifyUpload(makeFile("unknown", "x.txt"), null);
    expect(result.result).toBe("NOT_FOUND");
  });

  it("detects altered certificate record signature", async () => {
    const file = makeFile("signed", "s.txt");
    const certified = await certifyUpload(file);
    const cert = await prisma.certificate.findUniqueOrThrow({
      where: { certId: certified.certId },
    });
    await prisma.certificate.update({
      where: { id: cert.id },
      data: { signature: Buffer.alloc(64, 0).toString("base64") },
    });

    const result = await verifyUpload(
      makeFile("signed", "s.txt"),
      certified.certId,
    );
    expect(result.result).toBe("TAMPERED");
    expect(result.signatureValid).toBe(false);
  });
});
