import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "crypto";
import {
  getSigningProvider,
  LOCAL_ALG,
  setSigningProvider,
  type SignResult,
} from "./trust/keys";

export const SIGNATURE_ALG = LOCAL_ALG;

export interface SignaturePayload {
  certId: string;
  sha256: string;
  /** 64-bit hex phash; empty string for non-image certs */
  phash: string;
  width: number;
  height: number;
  createdAt: Date | string;
}

function canonical(payload: SignaturePayload): string {
  const createdAt =
    payload.createdAt instanceof Date
      ? payload.createdAt.toISOString()
      : new Date(payload.createdAt).toISOString();
  return `${payload.certId}|${payload.sha256}|${payload.phash}|${payload.width}|${payload.height}|${createdAt}`;
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

let cachedPrivate: KeyObject | null = null;
let cachedPublicPem: string | null = null;

export function getEd25519PrivateKey(envValue?: string): KeyObject {
  const raw = envValue ?? process.env.ED25519_PRIVATE_KEY;
  if (!raw) {
    throw new Error("ED25519_PRIVATE_KEY is not set");
  }
  if (!cachedPrivate || envValue) {
    const key = loadPrivateKey(raw);
    if (!envValue) cachedPrivate = key;
    return key;
  }
  return cachedPrivate;
}

/** SPKI PEM public key derived from the configured private key. */
export function getEd25519PublicKeyPem(envValue?: string): string {
  if (cachedPublicPem && !envValue) return cachedPublicPem;
  const priv = getEd25519PrivateKey(envValue);
  const pub = createPublicKey(priv);
  const pem = pub.export({ type: "spki", format: "pem" }).toString();
  if (!envValue) cachedPublicPem = pem;
  return pem;
}

/** Reset key cache (for tests). */
export function resetSigningKeyCache(): void {
  cachedPrivate = null;
  cachedPublicPem = null;
  setSigningProvider(null);
}

export function signCertificate(
  payload: SignaturePayload,
  privateKeyPem?: string,
): string {
  const key = getEd25519PrivateKey(privateKeyPem);
  const sig = cryptoSign(null, Buffer.from(canonical(payload), "utf8"), key);
  return sig.toString("base64");
}

/** Sign via the configured SigningProvider (includes keyId + alg). */
export async function signCertificateRecord(
  payload: SignaturePayload,
): Promise<SignResult> {
  return getSigningProvider().sign(Buffer.from(canonical(payload), "utf8"));
}

export function verifyCertificateSignature(
  payload: SignaturePayload,
  signature: string,
  publicKeyPem?: string,
): boolean {
  try {
    const pubPem = publicKeyPem ?? getEd25519PublicKeyPem();
    const pub = createPublicKey(pubPem);
    const sigBuf = Buffer.from(signature, "base64");
    return cryptoVerify(
      null,
      Buffer.from(canonical(payload), "utf8"),
      pub,
      sigBuf,
    );
  } catch {
    return false;
  }
}

/** Verify using a published keyId from the signing provider. */
export async function verifyCertificateSignatureWithKeyId(
  payload: SignaturePayload,
  signature: string,
  keyId: string,
): Promise<boolean> {
  const keys = await getSigningProvider().getPublicKeys();
  const key = keys.find((k) => k.keyId === keyId);
  if (!key) return false;
  return verifyCertificateSignature(payload, signature, key.publicKey);
}

export function payloadFromCert(cert: {
  certId: string;
  sha256: string;
  imagePhash?: string | null;
  width?: number | null;
  height?: number | null;
  createdAt: Date | string;
}): SignaturePayload {
  return {
    certId: cert.certId,
    sha256: cert.sha256,
    phash: cert.imagePhash ?? "",
    width: cert.width ?? 0,
    height: cert.height ?? 0,
    createdAt: cert.createdAt,
  };
}
