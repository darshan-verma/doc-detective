import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "crypto";
import type { PublicKeyInfo, SignResult, SigningProvider } from "./types";

export const LOCAL_ALG = "ed25519" as const;

interface KeySlot {
  keyId: string;
  privateKey: KeyObject;
  publicKeyPem: string;
  validFrom: Date;
  validTo: Date | null;
}

function loadPrivateKey(pemOrB64: string): KeyObject {
  const trimmed = pemOrB64.trim().replace(/\\n/g, "\n");
  if (trimmed.includes("BEGIN")) {
    return createPrivateKey(trimmed);
  }
  return createPrivateKey({
    key: Buffer.from(trimmed, "base64"),
    format: "der",
    type: "pkcs8",
  });
}

function publicPemFromPrivate(priv: KeyObject): string {
  return createPublicKey(priv)
    .export({ type: "spki", format: "pem" })
    .toString();
}

/**
 * Local Ed25519 keys from env.
 *
 * ED25519_PRIVATE_KEY — active private key (PEM or base64 PKCS8).
 * ED25519_KEY_ID — active key id (default "local-dev").
 * ED25519_PREVIOUS_KEYS — optional JSON array of
 *   { keyId, privateKey?, publicKey, validFrom, validTo } for rotation history.
 *   Prefer publicKey-only for retired keys so private material is not kept.
 */
export class LocalKeyProvider implements SigningProvider {
  private slots: KeySlot[] = [];
  private activeKeyId: string;

  constructor(options?: {
    privateKeyPem?: string;
    keyId?: string;
    previousKeysJson?: string;
  }) {
    const privatePem =
      options?.privateKeyPem ?? process.env.ED25519_PRIVATE_KEY;
    if (!privatePem) {
      throw new Error("ED25519_PRIVATE_KEY is not set");
    }
    const keyId =
      options?.keyId ?? process.env.ED25519_KEY_ID ?? "local-dev";
    const priv = loadPrivateKey(privatePem);
    this.activeKeyId = keyId;
    this.slots.push({
      keyId,
      privateKey: priv,
      publicKeyPem: publicPemFromPrivate(priv),
      validFrom: new Date(0),
      validTo: null,
    });

    const prevJson =
      options?.previousKeysJson ?? process.env.ED25519_PREVIOUS_KEYS;
    if (prevJson) {
      const parsed = JSON.parse(prevJson) as Array<{
        keyId: string;
        privateKey?: string;
        publicKey?: string;
        validFrom?: string;
        validTo?: string | null;
      }>;
      for (const entry of parsed) {
        if (this.slots.some((s) => s.keyId === entry.keyId)) continue;
        let privateKey: KeyObject;
        let publicKeyPem: string;
        if (entry.privateKey) {
          privateKey = loadPrivateKey(entry.privateKey);
          publicKeyPem = publicPemFromPrivate(privateKey);
        } else if (entry.publicKey) {
          // Retired key: verification-only stub private key unused for sign
          publicKeyPem = entry.publicKey.trim().replace(/\\n/g, "\n");
          privateKey = priv; // placeholder; sign() never selects retired keys
        } else {
          continue;
        }
        this.slots.push({
          keyId: entry.keyId,
          privateKey,
          publicKeyPem,
          validFrom: entry.validFrom ? new Date(entry.validFrom) : new Date(0),
          validTo: entry.validTo ? new Date(entry.validTo) : new Date(),
        });
      }
    }
  }

  async getActiveKeyId(): Promise<string> {
    return this.activeKeyId;
  }

  async sign(bytes: Buffer | Uint8Array): Promise<SignResult> {
    const slot = this.slots.find((s) => s.keyId === this.activeKeyId);
    if (!slot || slot.validTo !== null) {
      throw new Error(`Active signing key ${this.activeKeyId} is not available`);
    }
    const sig = cryptoSign(null, Buffer.from(bytes), slot.privateKey);
    return {
      signature: sig.toString("base64"),
      keyId: slot.keyId,
      alg: LOCAL_ALG,
    };
  }

  async getPublicKeys(): Promise<PublicKeyInfo[]> {
    return this.slots.map((s) => ({
      keyId: s.keyId,
      alg: LOCAL_ALG,
      publicKey: s.publicKeyPem,
      validFrom: s.validFrom,
      validTo: s.validTo,
    }));
  }

  /** Test helper: rotate to a freshly generated key, keeping old public key. */
  rotateForTest(newKeyId: string): { oldKeyId: string; newKeyId: string } {
    const old = this.slots.find((s) => s.keyId === this.activeKeyId)!;
    old.validTo = new Date();
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.slots.push({
      keyId: newKeyId,
      privateKey,
      publicKeyPem: publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      validFrom: new Date(),
      validTo: null,
    });
    this.activeKeyId = newKeyId;
    return { oldKeyId: old.keyId, newKeyId };
  }
}
