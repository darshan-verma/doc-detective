import { generateKeyPairSync } from "crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  resetSigningKeyCache,
  signCertificate,
  verifyCertificateSignature,
  getEd25519PublicKeyPem,
} from "../src/lib/signing";

describe("ed25519 signing", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  const payload = {
    certId: "K7X2M9",
    sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    phash: "0123456789abcdef",
    width: 64,
    height: 64,
    createdAt: new Date("2024-01-01T00:00:00.000Z"),
  };

  beforeAll(() => {
    process.env.ED25519_PRIVATE_KEY = privatePem;
    resetSigningKeyCache();
  });

  it("signs and verifies a certificate payload", () => {
    const sig = signCertificate(payload, privatePem);
    expect(sig.length).toBeGreaterThan(40);
    expect(verifyCertificateSignature(payload, sig, publicPem)).toBe(true);
  });

  it("fails verification when payload is altered", () => {
    const sig = signCertificate(payload, privatePem);
    expect(
      verifyCertificateSignature(
        { ...payload, width: 65 },
        sig,
        publicPem,
      ),
    ).toBe(false);
  });

  it("exposes a public key derived from the private key", () => {
    const pem = getEd25519PublicKeyPem(privatePem);
    expect(pem).toContain("BEGIN PUBLIC KEY");
    expect(pem.replace(/\s/g, "")).toBe(publicPem.replace(/\s/g, ""));
  });

  it("fails verification with tampered signature bytes", () => {
    const sig = signCertificate(payload, privatePem);
    const buf = Buffer.from(sig, "base64");
    buf[0] = (buf[0]! + 1) % 256;
    expect(
      verifyCertificateSignature(payload, buf.toString("base64"), publicPem),
    ).toBe(false);
  });
});
