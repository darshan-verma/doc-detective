import { generateKeyPairSync } from "crypto";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { PrismaClient } from "@prisma/client";
import { resetConfigCache } from "../src/lib/config";
import { resetSigningKeyCache } from "../src/lib/signing";
import {
  appendLogEntry,
  computeEntryHash,
  GENESIS_PREV_HASH,
  verifyLogChain,
} from "../src/lib/trust/log";

const prisma = new PrismaClient();

beforeAll(() => {
  const { privateKey } = generateKeyPairSync("ed25519");
  process.env.ED25519_PRIVATE_KEY = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  process.env.DATABASE_URL =
    process.env.DATABASE_URL || "file:./prisma/dev.db";
  resetConfigCache();
  resetSigningKeyCache();
});

beforeEach(async () => {
  await prisma.certificate.deleteMany();
  await prisma.logEntry.deleteMany();
  await prisma.checkpoint.deleteMany();
});

describe("hash-chained log", () => {
  it("appends with genesis prevHash then chains entryHash", async () => {
    const a = await appendLogEntry({
      certId: "AAAA",
      eventType: "CERTIFICATE_CREATED",
      recordHash: "r1",
    });
    expect(a.seq).toBe(1);
    expect(a.prevHash).toBe(GENESIS_PREV_HASH);
    expect(a.entryHash).toBe(
      computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash: "r1",
        createdAt: a.createdAt,
      }),
    );

    const b = await appendLogEntry({
      certId: "BBBB",
      eventType: "CERTIFICATE_CREATED",
      recordHash: "r2",
    });
    expect(b.seq).toBe(2);
    expect(b.prevHash).toBe(a.entryHash);

    const ok = await verifyLogChain();
    expect(ok.ok).toBe(true);
    expect(ok.brokenAt).toBeNull();
  });

  it("detects tampering at the broken seq", async () => {
    await appendLogEntry({
      eventType: "CERTIFICATE_CREATED",
      recordHash: "r1",
      certId: "A",
    });
    await appendLogEntry({
      eventType: "CERTIFICATE_CREATED",
      recordHash: "r2",
      certId: "B",
    });
    await appendLogEntry({
      eventType: "CERTIFICATE_CREATED",
      recordHash: "r3",
      certId: "C",
    });

    await prisma.logEntry.update({
      where: { seq: 2 },
      data: { recordHash: "TAMPERED" },
    });

    const result = await verifyLogChain();
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(2);
  });

  it("detects prevHash fork", async () => {
    await appendLogEntry({
      eventType: "KEY_ROTATION",
      recordHash: "k1",
    });
    await appendLogEntry({
      eventType: "KEY_ROTATION",
      recordHash: "k2",
    });

    await prisma.logEntry.update({
      where: { seq: 2 },
      data: { prevHash: "0".repeat(64) },
    });

    const result = await verifyLogChain(1, 2);
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.reason).toMatch(/prevHash/);
  });
});
