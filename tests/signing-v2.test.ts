/**
 * Pure unit tests for certificate signature v2 + revoke recordHash (no DB).
 */
import { generateKeyPairSync } from "crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildAnalysisDigest,
  canonicalJson,
  canonicalV2Bytes,
  payloadFromCert,
  resetSigningKeyCache,
  signCertificate,
  signCertificateRecordV2,
  verifyCertificateSignature,
  verifyCertificateSignatureV2,
  type SignaturePayloadV2,
} from "../src/lib/signing";
import { hashRevokeRecord } from "../src/lib/trust/log";

const baseAnalysis = {
  chunkHashes: ["aaa", "bbb"],
  imagePhash: "0123456789abcdef",
  width: 64,
  height: 48,
  gridSize: 32,
  cellSignatures: [
    { dHash: "1", meanLuma: 10 },
    { dHash: "2", meanLuma: 20 },
  ],
  watermarkBits: [1, 0, 1, 0],
  watermarkVersion: 1,
  textSimhash: null as string | null,
};

function makeV2(
  overrides: Partial<SignaturePayloadV2> = {},
): SignaturePayloadV2 {
  return {
    certId: "DDTESTCERT0001",
    sha256: "a".repeat(64),
    inputSha256: "b".repeat(64),
    sizeBytes: 100,
    mimeType: "image/png",
    createdAt: new Date("2024-06-01T12:00:00.000Z"),
    keyId: "local-dev",
    parentCertId: null,
    version: 1,
    similarToCertId: null,
    ...baseAnalysis,
    ...overrides,
  };
}

describe("canonical JSON", () => {
  it("is stable under key order", () => {
    const a = canonicalJson({ z: 1, a: { y: 2, b: 3 }, m: [1, 2] });
    const b = canonicalJson({ a: { b: 3, y: 2 }, m: [1, 2], z: 1 });
    expect(a).toBe(b);
  });

  it("is stable under array JSON formatting differences for analysisDigest", () => {
    const cellsCompact = [{ dHash: "1", meanLuma: 10 }];
    const cellsReordered = [{ meanLuma: 10, dHash: "1" }];
    expect(buildAnalysisDigest({ ...baseAnalysis, cellSignatures: cellsCompact })).toBe(
      buildAnalysisDigest({
        ...baseAnalysis,
        cellSignatures: cellsReordered,
      }),
    );
  });
});

describe("signature payload v2", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  beforeAll(() => {
    process.env.ED25519_PRIVATE_KEY = privatePem;
    process.env.ED25519_KEY_ID = "local-dev";
    resetSigningKeyCache();
  });

  it("signs and verifies a v2 payload", async () => {
    const payload = makeV2();
    const signed = await signCertificateRecordV2(payload);
    expect(
      verifyCertificateSignatureV2(
        { ...payload, keyId: signed.keyId },
        signed.signature,
        publicPem,
      ),
    ).toBe(true);
  });

  it("fails verification when any v2 top-level field changes", async () => {
    const payload = makeV2();
    const signed = await signCertificateRecordV2(payload);
    const fields: Array<keyof SignaturePayloadV2> = [
      "certId",
      "sha256",
      "inputSha256",
      "sizeBytes",
      "mimeType",
      "keyId",
      "parentCertId",
      "version",
      "similarToCertId",
    ];
    for (const field of fields) {
      const tweaked = { ...payload, keyId: signed.keyId } as SignaturePayloadV2;
      if (field === "sizeBytes" || field === "version") {
        (tweaked as Record<string, unknown>)[field] =
          (tweaked[field] as number) + 1;
      } else if (field === "parentCertId" || field === "similarToCertId") {
        (tweaked as Record<string, unknown>)[field] = "OTHER";
      } else if (field === "keyId") {
        tweaked.keyId = "other-key";
      } else {
        (tweaked as Record<string, unknown>)[field] = String(tweaked[field]) + "x";
      }
      expect(
        verifyCertificateSignatureV2(tweaked, signed.signature, publicPem),
        `field ${field}`,
      ).toBe(false);
    }
  });

  it("fails verification when any analysisDigest field changes", async () => {
    const payload = makeV2();
    const signed = await signCertificateRecordV2(payload);
    const mutants: SignaturePayloadV2[] = [
      makeV2({ chunkHashes: ["aaa", "CCC"] }),
      makeV2({ imagePhash: "ffffffffffffffff" }),
      makeV2({ width: 65 }),
      makeV2({ height: 49 }),
      makeV2({ gridSize: 16 }),
      makeV2({
        cellSignatures: [{ dHash: "9", meanLuma: 10 }],
      }),
      makeV2({ watermarkBits: [0, 0, 0, 0] }),
      makeV2({ watermarkVersion: 99 }),
      makeV2({ textSimhash: "deadbeef" }),
    ];
    for (const m of mutants) {
      expect(
        verifyCertificateSignatureV2(
          { ...m, keyId: signed.keyId },
          signed.signature,
          publicPem,
        ),
      ).toBe(false);
    }
  });

  it("v1 records still verify with the v1 canonical form", () => {
    const payload = {
      certId: "LEGACY1",
      sha256: "c".repeat(64),
      phash: "0123456789abcdef",
      width: 10,
      height: 10,
      createdAt: new Date("2023-01-01T00:00:00.000Z"),
    };
    const sig = signCertificate(payload, privatePem);
    expect(verifyCertificateSignature(payload, sig, publicPem)).toBe(true);
    expect(payloadFromCert({ ...payload, imagePhash: payload.phash }).phash).toBe(
      payload.phash,
    );
  });

  it("canonicalV2Bytes is domain-prefixed", () => {
    const bytes = canonicalV2Bytes(makeV2());
    expect(bytes.toString("utf8").startsWith("doc-detective/cert/v2\n")).toBe(
      true,
    );
  });
});

describe("revoke recordHash", () => {
  it("changes when reason or revokedAt changes", () => {
    const base = hashRevokeRecord({
      certId: "C1",
      revokedAt: "2024-01-01T00:00:00.000Z",
      reason: "lost key",
    });
    expect(
      hashRevokeRecord({
        certId: "C1",
        revokedAt: "2024-01-01T00:00:00.000Z",
        reason: "other",
      }),
    ).not.toBe(base);
    expect(
      hashRevokeRecord({
        certId: "C1",
        revokedAt: "2024-01-02T00:00:00.000Z",
        reason: "lost key",
      }),
    ).not.toBe(base);
    expect(
      hashRevokeRecord({
        certId: "C1",
        revokedAt: new Date("2024-01-01T00:00:00.000Z"),
        reason: "lost key",
      }),
    ).toBe(base);
  });
});
