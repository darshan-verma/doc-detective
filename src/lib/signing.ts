import {
  createHash,
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

/** Domain-separated prefix for certificate signature payload v2. */
export const CERT_SIGNATURE_DOMAIN_V2 = "doc-detective/cert/v2\n";

/** Legacy v1 payload (narrow). */
export interface SignaturePayload {
  certId: string;
  sha256: string;
  /** 64-bit hex phash; empty string for non-image certs */
  phash: string;
  width: number;
  height: number;
  createdAt: Date | string;
}

/** Analysis fields hashed into analysisDigest for v2. */
export interface AnalysisDigestInput {
  chunkHashes: string[] | null;
  imagePhash: string | null;
  width: number | null;
  height: number | null;
  gridSize: number | null;
  cellSignatures: unknown | null;
  watermarkBits: unknown | null;
  watermarkVersion: number | null;
  textSimhash: string | null;
}

/** Full v2 signing payload (all verification inputs). */
export interface SignaturePayloadV2 extends AnalysisDigestInput {
  certId: string;
  sha256: string;
  inputSha256: string | null;
  sizeBytes: number;
  mimeType: string;
  createdAt: Date | string;
  keyId: string;
  parentCertId: string | null;
  version: number;
  similarToCertId: string | null;
}

/**
 * Canonical JSON: keys sorted recursively, no whitespace, numbers as-is,
 * null preserved. Arrays keep order; elements are canonicalized.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    out[key] = sortKeysDeep(obj[key]);
  }
  return out;
}

function toIso(createdAt: Date | string): string {
  return createdAt instanceof Date
    ? createdAt.toISOString()
    : new Date(createdAt).toISOString();
}

function parseJsonField<T>(raw: string | null | undefined): T | null {
  if (raw == null || raw === "") return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function buildAnalysisDigest(input: AnalysisDigestInput): string {
  return createHash("sha256")
    .update(
      canonicalJson({
        chunkHashes: input.chunkHashes,
        imagePhash: input.imagePhash,
        width: input.width,
        height: input.height,
        gridSize: input.gridSize,
        cellSignatures: input.cellSignatures,
        watermarkBits: input.watermarkBits,
        watermarkVersion: input.watermarkVersion,
        textSimhash: input.textSimhash,
      }),
      "utf8",
    )
    .digest("hex");
}

function canonicalV1(payload: SignaturePayload): string {
  return `${payload.certId}|${payload.sha256}|${payload.phash}|${payload.width}|${payload.height}|${toIso(payload.createdAt)}`;
}

/** UTF-8 bytes signed for v2 (domain prefix + canonical JSON body). */
export function canonicalV2Bytes(payload: SignaturePayloadV2): Buffer {
  const analysisDigest = buildAnalysisDigest(payload);
  const body = canonicalJson({
    v: 2,
    certId: payload.certId,
    sha256: payload.sha256,
    inputSha256: payload.inputSha256,
    sizeBytes: payload.sizeBytes,
    mimeType: payload.mimeType,
    createdAt: toIso(payload.createdAt),
    keyId: payload.keyId,
    parentCertId: payload.parentCertId,
    version: payload.version,
    similarToCertId: payload.similarToCertId,
    analysisDigest,
  });
  return Buffer.from(CERT_SIGNATURE_DOMAIN_V2 + body, "utf8");
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

/** @deprecated Prefer signCertificateRecord / v2. Kept for v1 unit tests. */
export function signCertificate(
  payload: SignaturePayload,
  privateKeyPem?: string,
): string {
  const key = getEd25519PrivateKey(privateKeyPem);
  const sig = cryptoSign(null, Buffer.from(canonicalV1(payload), "utf8"), key);
  return sig.toString("base64");
}

/** Sign via the configured SigningProvider (v1 narrow payload). */
export async function signCertificateRecord(
  payload: SignaturePayload,
): Promise<SignResult> {
  return getSigningProvider().sign(Buffer.from(canonicalV1(payload), "utf8"));
}

/** Sign a v2 payload covering all verification inputs. */
export async function signCertificateRecordV2(
  payload: Omit<SignaturePayloadV2, "keyId"> & { keyId?: string },
): Promise<SignResult> {
  const provider = getSigningProvider();
  const keyId = payload.keyId ?? (await provider.getActiveKeyId());
  const bytes = canonicalV2Bytes({ ...payload, keyId });
  return provider.sign(bytes);
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
      Buffer.from(canonicalV1(payload), "utf8"),
      pub,
      sigBuf,
    );
  } catch {
    return false;
  }
}

export function verifyCertificateSignatureV2(
  payload: SignaturePayloadV2,
  signature: string,
  publicKeyPem?: string,
): boolean {
  try {
    const pubPem = publicKeyPem ?? getEd25519PublicKeyPem();
    const pub = createPublicKey(pubPem);
    const sigBuf = Buffer.from(signature, "base64");
    return cryptoVerify(null, canonicalV2Bytes(payload), pub, sigBuf);
  } catch {
    return false;
  }
}

/** Verify using a published keyId from the signing provider (v1). */
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

export async function verifyCertificateSignatureV2WithKeyId(
  payload: SignaturePayloadV2,
  signature: string,
  keyId: string,
): Promise<boolean> {
  const keys = await getSigningProvider().getPublicKeys();
  const key = keys.find((k) => k.keyId === keyId);
  if (!key) return false;
  return verifyCertificateSignatureV2(payload, signature, key.publicKey);
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

/** Build v2 payload from a Certificate row (parses JSON analysis fields). */
export function payloadFromCertV2(cert: {
  certId: string;
  sha256: string;
  inputSha256?: string | null;
  sizeBytes: number;
  mimeType: string;
  createdAt: Date | string;
  keyId: string;
  parentCertId?: string | null;
  version: number;
  similarToCertId?: string | null;
  chunkHashes: string;
  imagePhash?: string | null;
  width?: number | null;
  height?: number | null;
  gridSize?: number | null;
  cellSignatures?: string | null;
  watermarkBits?: string | null;
  watermarkVersion?: number | null;
  textSimhash?: string | null;
}): SignaturePayloadV2 {
  return {
    certId: cert.certId,
    sha256: cert.sha256,
    inputSha256: cert.inputSha256 ?? null,
    sizeBytes: cert.sizeBytes,
    mimeType: cert.mimeType,
    createdAt: cert.createdAt,
    keyId: cert.keyId,
    parentCertId: cert.parentCertId ?? null,
    version: cert.version,
    similarToCertId: cert.similarToCertId ?? null,
    chunkHashes: parseJsonField<string[]>(cert.chunkHashes),
    imagePhash: cert.imagePhash ?? null,
    width: cert.width ?? null,
    height: cert.height ?? null,
    gridSize: cert.gridSize ?? null,
    cellSignatures: parseJsonField(cert.cellSignatures),
    watermarkBits: parseJsonField(cert.watermarkBits),
    watermarkVersion: cert.watermarkVersion ?? null,
    textSimhash: cert.textSimhash ?? null,
  };
}

export function isLegacySignatureVersion(
  signatureVersion: number | null | undefined,
): boolean {
  return (signatureVersion ?? 1) < 2;
}
