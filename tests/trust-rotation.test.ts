import { describe, expect, it } from "vitest";
import {
  payloadFromCert,
  verifyCertificateSignatureWithKeyId,
} from "../src/lib/signing";
import { LocalKeyProvider } from "../src/lib/trust/keys/local";

describe("key rotation", () => {
  it("verifies a record signed with an old key after rotation", async () => {
    const { privateKey } = await import("crypto").then((c) =>
      c.generateKeyPairSync("ed25519"),
    );
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const provider = new LocalKeyProvider({
      privateKeyPem: pem,
      keyId: "key-v1",
    });

    const payload = payloadFromCert({
      certId: "TESTCERT000000000000000001",
      sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      createdAt: new Date("2024-06-01T00:00:00.000Z"),
    });

    const signed = await provider.sign(
      Buffer.from(
        `${payload.certId}|${payload.sha256}|${payload.phash}|${payload.width}|${payload.height}|${new Date(payload.createdAt).toISOString()}`,
        "utf8",
      ),
    );
    expect(signed.keyId).toBe("key-v1");

    provider.rotateForTest("key-v2");
    expect(await provider.getActiveKeyId()).toBe("key-v2");

    const keys = await provider.getPublicKeys();
    expect(keys.find((k) => k.keyId === "key-v1")?.validTo).not.toBeNull();
    expect(keys.find((k) => k.keyId === "key-v2")?.validTo).toBeNull();

    // Old signature still verifies against key-v1 public key
    const oldPub = keys.find((k) => k.keyId === "key-v1")!.publicKey;
    const { verifyCertificateSignature } = await import("../src/lib/signing");
    expect(
      verifyCertificateSignature(payload, signed.signature, oldPub),
    ).toBe(true);

    // And via keyId lookup on the provider's published set
    // (wire provider into getSigningProvider for WithKeyId)
    const { setSigningProvider } = await import("../src/lib/trust/keys");
    setSigningProvider(provider);
    expect(
      await verifyCertificateSignatureWithKeyId(
        payload,
        signed.signature,
        "key-v1",
      ),
    ).toBe(true);

    // New signatures use key-v2
    const signed2 = await provider.sign(Buffer.from("hello"));
    expect(signed2.keyId).toBe("key-v2");
    setSigningProvider(null);
  });
});
