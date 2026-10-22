import { createHash } from "crypto";
import { mkdir, writeFile } from "fs/promises";
import path from "path";
import { Readable } from "stream";
import type { Certificate } from "@prisma/client";
import { getConfig, WATERMARK_VERSION } from "../config";
import { AppError } from "../errors";
import { certifiedFilename, sanitizeFilename } from "../filenames";
import { hashBuffer, hashStream } from "../hashing";
import {
  cellSignatures,
  decodeImage,
  embedCertId,
  encodePng,
  hamming,
  isCertifiableImage,
  phash64,
} from "../image";
import {
  identifyFile,
  isStrongCandidate,
  textSimhash64,
  type IdentifyResult,
  type PublicCertificateFields,
  type SimilarityCandidate,
} from "../identify";
import { extractTextForSimhash, isDocumentForSimhash } from "../identify/text";
import { prisma } from "../prisma";
import {
  getEd25519PublicKeyPem,
  payloadFromCert,
  signCertificateRecord,
  verifyCertificateSignature,
  verifyCertificateSignatureWithKeyId,
} from "../signing";
import { getStorage } from "../storage";
import {
  appendLogEntry,
  formatCertId,
  generateCertId,
  hashCertificateRecord,
  normalizeCertId,
  syncPublicKeysToDb,
  watermarkTokenFromCertId,
} from "../trust";
import { assertOwnerToken, issueOwnerToken } from "./ownership";
import { publicCertificateView } from "./public-view";
import { stampImage, stampPdf } from "../stamp";

export { publicCertificateView } from "./public-view";

export interface CertifyOptions {
  addVerificationStamp?: boolean;
  parentCertId?: string | null;
  ownerToken?: string | null;
  visibility?: "PUBLIC" | "LIMITED";
  origin?: string;
  /** Bypass similarity block and link similarToCertId. */
  force?: boolean;
  /** Skip identify (internal); normally always run. */
  skipIdentify?: boolean;
}

export interface CertifyResult {
  status: "CREATED";
  certId: string;
  certIdDisplay: string;
  sha256: string;
  inputSha256?: string;
  certifiedFileName: string;
  downloadUrl: string;
  sizeBytes: number;
  keyId: string;
  timestampStatus: string;
  /** Returned once — store securely; only a hash is kept server-side. */
  ownerToken: string;
  version: number;
  parentCertId?: string | null;
  similarToCertId?: string | null;
  stamped?: boolean;
  isImage?: boolean;
  width?: number;
  height?: number;
  imagePhash?: string;
}

export type CertifyOutcome =
  | CertifyResult
  | {
      status: "ALREADY_CERTIFIED";
      certificate: PublicCertificateFields;
      matchedOn: "sha256" | "inputSha256";
    }
  | {
      status: "ALREADY_CERTIFIED_REVOKED";
      certificate: PublicCertificateFields;
      matchedOn: "sha256" | "inputSha256";
      revocationNotice: string;
    };

function guessMime(filename: string, provided: string | null): string {
  if (provided && provided !== "application/octet-stream") return provided;
  const ext = path.extname(filename).toLowerCase();
  const map: Record<string, string> = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".docx":
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
  };
  return map[ext] ?? "application/octet-stream";
}

async function allocateCertId(): Promise<string> {
  for (let attempt = 0; attempt < 8; attempt++) {
    const certId = generateCertId();
    const existing = await prisma.certificate.findUnique({ where: { certId } });
    if (!existing) return certId;
  }
  throw new AppError("INTERNAL", "Could not allocate a unique certificate ID", 500);
}

async function persistCertificate(args: {
  certId: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  inputSha256: string;
  textSimhash?: string | null;
  similarToCertId?: string | null;
  storagePath: string;
  chunkHashes: string[];
  createdAt: Date;
  visibility?: "PUBLIC" | "LIMITED";
  ownerTokenHash: string;
  parentCertId?: string | null;
  version?: number;
  width?: number;
  height?: number;
  imagePhash?: string;
  gridSize?: number;
  cellSignatures?: unknown;
  watermarkBits?: unknown;
  watermarkVersion?: number;
}): Promise<Certificate> {
  await syncPublicKeysToDb();
  const signed = await signCertificateRecord(
    payloadFromCert({
      certId: args.certId,
      sha256: args.sha256,
      imagePhash: args.imagePhash,
      width: args.width,
      height: args.height,
      createdAt: args.createdAt,
    }),
  );

  const recordHash = hashCertificateRecord({
    certId: args.certId,
    sha256: args.sha256,
    sizeBytes: args.sizeBytes,
    keyId: signed.keyId,
    signature: signed.signature,
    createdAt: args.createdAt,
  });

  try {
    return await prisma.$transaction(async (tx) => {
      // Re-check exact match inside the transaction to close the race window.
      const raced =
        (await tx.certificate.findFirst({
          where: {
            OR: [
              { sha256: args.inputSha256 },
              { inputSha256: args.inputSha256 },
              { sha256: args.sha256 },
            ],
          },
        })) ?? null;
      if (raced) {
        throw new ExactMatchRace(raced);
      }

      const cert = await tx.certificate.create({
        data: {
          certId: args.certId,
          originalName: args.originalName,
          mimeType: args.mimeType,
          sizeBytes: args.sizeBytes,
          sha256: args.sha256,
          inputSha256: args.inputSha256,
          textSimhash: args.textSimhash ?? null,
          similarToCertId: args.similarToCertId ?? null,
          storagePath: args.storagePath,
          signature: signed.signature,
          signatureAlg: signed.alg,
          keyId: signed.keyId,
          chunkHashes: JSON.stringify(args.chunkHashes),
          visibility: args.visibility ?? "LIMITED",
          timestampStatus: "PENDING",
          ownerTokenHash: args.ownerTokenHash,
          parentCertId: args.parentCertId ?? null,
          version: args.version ?? 1,
          width: args.width,
          height: args.height,
          imagePhash: args.imagePhash,
          gridSize: args.gridSize ?? 32,
          cellSignatures: args.cellSignatures
            ? JSON.stringify(args.cellSignatures)
            : null,
          watermarkBits: args.watermarkBits
            ? JSON.stringify(args.watermarkBits)
            : null,
          watermarkVersion: args.watermarkVersion,
          createdAt: args.createdAt,
        },
      });

      if (args.parentCertId) {
        await tx.certificate.update({
          where: { certId: args.parentCertId },
          data: { supersededBy: args.certId },
        });
      }

      await appendLogEntry(
        {
          certId: args.certId,
          eventType: "CERTIFICATE_CREATED",
          recordHash,
          createdAt: args.createdAt,
          details: args.similarToCertId
            ? { similarToCertId: args.similarToCertId }
            : null,
        },
        tx,
      );

      return cert;
    });
  } catch (err) {
    if (err instanceof ExactMatchRace) {
      throw err;
    }
    // Unique constraint race on sha256 / inputSha256
    if (
      err &&
      typeof err === "object" &&
      "code" in err &&
      (err as { code: string }).code === "P2002"
    ) {
      const existing = await prisma.certificate.findFirst({
        where: {
          OR: [
            { sha256: args.inputSha256 },
            { inputSha256: args.inputSha256 },
            { sha256: args.sha256 },
            { inputSha256: args.sha256 },
          ],
        },
      });
      if (existing) throw new ExactMatchRace(existing);
    }
    throw err;
  }
}

/** Thrown when a concurrent insert loses the race to an identical file. */
export class ExactMatchRace extends Error {
  constructor(public readonly certificate: Certificate) {
    super("EXACT_MATCH_RACE");
    this.name = "ExactMatchRace";
  }
}

async function certifyImage(
  file: File,
  originalName: string,
  _mimeType: string,
  options: CertifyOptions,
  versionMeta: {
    parentCertId: string | null;
    version: number;
    similarToCertId: string | null;
  },
  inputSha256: string,
): Promise<CertifyResult> {
  const config = getConfig();
  const certId = await allocateCertId();
  const { token: ownerToken, hash: ownerTokenHash } = issueOwnerToken();
  const watermarkToken = watermarkTokenFromCertId(certId);
  let inputBytes = Buffer.from(await file.arrayBuffer());

  // Stamp FIRST when requested, then watermark + hash the stamped output
  let stamped = false;
  if (options.addVerificationStamp) {
    inputBytes = await stampImage(inputBytes, certId, options.origin);
    stamped = true;
  }

  const pixels = await decodeImage(inputBytes);

  const { pixels: watermarked, payloadBits } = embedCertId(
    pixels,
    watermarkToken,
    {
      key: config.watermarkKey,
      step: config.watermarkQimStep,
    },
  );

  const pngBytes = await encodePng(watermarked);
  const hashResult = await hashBuffer(pngBytes);
  const imagePhash = phash64(watermarked);
  const gridSize = config.imageGridSize;
  const cells = cellSignatures(watermarked, gridSize);

  const createdAt = new Date();
  const storageKey = `${certId}/${path.parse(originalName).name || "image"}.png`;
  const storage = getStorage();
  const absPath =
    storage.resolvePath?.(storageKey) ??
    path.join(config.storageDir, storageKey);
  await mkdir(path.dirname(absPath), { recursive: true });
  await writeFile(absPath, pngBytes);

  const cert = await persistCertificate({
    certId,
    originalName,
    mimeType: "image/png",
    sizeBytes: hashResult.sizeBytes,
    sha256: hashResult.sha256,
    inputSha256,
    similarToCertId: versionMeta.similarToCertId,
    storagePath: storageKey,
    chunkHashes: hashResult.chunkHashes,
    createdAt,
    visibility: options.visibility,
    ownerTokenHash,
    parentCertId: versionMeta.parentCertId,
    version: versionMeta.version,
    width: watermarked.width,
    height: watermarked.height,
    imagePhash,
    gridSize,
    cellSignatures: cells,
    watermarkBits: payloadBits,
    watermarkVersion: WATERMARK_VERSION,
  });

  const certifiedFileName = certifiedFilename(originalName, certId, {
    forceExt: ".png",
  });

  return {
    status: "CREATED",
    certId,
    certIdDisplay: formatCertId(certId),
    sha256: hashResult.sha256,
    inputSha256,
    certifiedFileName,
    downloadUrl: `/api/download/${certId}`,
    sizeBytes: hashResult.sizeBytes,
    keyId: cert.keyId,
    timestampStatus: cert.timestampStatus,
    ownerToken,
    version: cert.version,
    parentCertId: cert.parentCertId,
    similarToCertId: cert.similarToCertId,
    stamped,
    isImage: true,
    width: watermarked.width,
    height: watermarked.height,
    imagePhash,
  };
}

async function certifyGeneric(
  file: File,
  originalName: string,
  mimeType: string,
  options: CertifyOptions,
  versionMeta: {
    parentCertId: string | null;
    version: number;
    similarToCertId: string | null;
  },
  inputSha256: string,
  textSimhash: string | null,
): Promise<CertifyResult> {
  const config = getConfig();
  const certId = await allocateCertId();
  const { token: ownerToken, hash: ownerTokenHash } = issueOwnerToken();

  let bytes = Buffer.from(await file.arrayBuffer());
  let stamped = false;
  if (
    options.addVerificationStamp &&
    (mimeType === "application/pdf" || originalName.toLowerCase().endsWith(".pdf"))
  ) {
    bytes = await stampPdf(bytes, certId, options.origin);
    stamped = true;
  }

  if (bytes.length === 0) {
    throw new AppError("EMPTY_FILE", "Empty files are not allowed", 400);
  }

  const hashResult = await hashBuffer(bytes);

  const storageKey = `${certId}/${originalName}`;
  const storage = getStorage();
  const absPath =
    storage.resolvePath?.(storageKey) ??
    path.join(config.storageDir, storageKey);

  await mkdir(path.dirname(absPath), { recursive: true });
  await writeFile(absPath, bytes);

  const createdAt = new Date();
  const cert = await persistCertificate({
    certId,
    originalName,
    mimeType,
    sizeBytes: hashResult.sizeBytes,
    sha256: hashResult.sha256,
    inputSha256,
    textSimhash,
    similarToCertId: versionMeta.similarToCertId,
    storagePath: storageKey,
    chunkHashes: hashResult.chunkHashes,
    createdAt,
    visibility: options.visibility,
    ownerTokenHash,
    parentCertId: versionMeta.parentCertId,
    version: versionMeta.version,
  });

  const certifiedFileName = certifiedFilename(originalName, certId);

  return {
    status: "CREATED",
    certId,
    certIdDisplay: formatCertId(certId),
    sha256: hashResult.sha256,
    inputSha256,
    certifiedFileName,
    downloadUrl: `/api/download/${certId}`,
    sizeBytes: hashResult.sizeBytes,
    keyId: cert.keyId,
    timestampStatus: cert.timestampStatus,
    ownerToken,
    version: cert.version,
    parentCertId: cert.parentCertId,
    similarToCertId: cert.similarToCertId,
    stamped,
    isImage: false,
  };
}

function alreadyCertifiedOutcome(
  identified: Extract<IdentifyResult, { kind: "EXACT" }>,
): CertifyOutcome {
  if (identified.revokedAt) {
    return {
      status: "ALREADY_CERTIFIED_REVOKED",
      certificate: identified.certificate,
      matchedOn: identified.matchedOn,
      revocationNotice: identified.revokeReason
        ? `This certificate was revoked: ${identified.revokeReason}`
        : "This certificate was revoked.",
    };
  }
  return {
    status: "ALREADY_CERTIFIED",
    certificate: identified.certificate,
    matchedOn: identified.matchedOn,
  };
}

function filterSimilarityForParent(
  candidates: SimilarityCandidate[],
  parentCertId: string | null,
): SimilarityCandidate[] {
  if (!parentCertId) return candidates.filter(isStrongCandidate);
  return candidates
    .filter((c) => c.certId !== parentCertId)
    .filter(isStrongCandidate);
}

export async function certifyUpload(
  file: File,
  options: CertifyOptions = {},
): Promise<CertifyOutcome> {
  const config = getConfig();
  const originalName = sanitizeFilename(file.name || "file");

  if (file.size === 0) {
    throw new AppError("EMPTY_FILE", "Empty files are not allowed", 400);
  }
  if (file.size > config.maxUploadBytes) {
    throw new AppError(
      "FILE_TOO_LARGE",
      `File exceeds maximum size of ${config.maxUploadBytes / (1024 * 1024)} MB`,
      413,
    );
  }

  let parentCertId: string | null = null;
  let version = 1;
  if (options.parentCertId) {
    if (!options.ownerToken) {
      throw new AppError(
        "BAD_REQUEST",
        "ownerToken is required when creating a new version",
        400,
      );
    }
    const parentId = normalizeCertId(options.parentCertId);
    if (!parentId) {
      throw new AppError("BAD_REQUEST", "Invalid parentCertId", 400);
    }
    await assertOwnerToken(parentId, options.ownerToken);
    const parent = await prisma.certificate.findUnique({
      where: { certId: parentId },
    });
    if (!parent) {
      throw new AppError("NOT_FOUND", "Parent certificate not found", 404);
    }
    parentCertId = parentId;
    version = parent.version + 1;
  }

  const mimeType = guessMime(originalName, file.type || null);
  const bytes = Buffer.from(await file.arrayBuffer());
  const { sha256: inputSha256 } = await hashBuffer(bytes);

  // Identify before creating (exact / similar / new).
  const identified = options.skipIdentify
    ? ({ kind: "NEW" } as IdentifyResult)
    : await identifyFile({ bytes, name: originalName, type: mimeType });

  if (identified.kind === "EXACT") {
    return alreadyCertifiedOutcome(identified);
  }

  let similarToCertId: string | null = null;

  if (identified.kind === "LIKELY_MODIFIED_COPY") {
    const blocking = filterSimilarityForParent(
      identified.candidates,
      parentCertId,
    );
    if (blocking.length > 0) {
      if (!options.force) {
        throw new AppError(
          "SIMILAR_CERTIFICATE_EXISTS",
          "This file looks like a modified copy of an existing certificate",
          409,
          {
            candidates: blocking.map((c) => ({
              certId: c.certId,
              signals: c.signals,
              score: c.score,
              filenameOnly: c.filenameOnly,
              certificate: c.certificate,
            })),
          },
        );
      }
      // force=true: link to the strongest candidate
      similarToCertId = blocking[0]!.certId;
    }
    // Filename-only (weak) candidates do not block and are not linked.
  }

  const versionMeta = { parentCertId, version, similarToCertId };

  let textSimhash: string | null = null;
  if (isDocumentForSimhash(originalName, mimeType)) {
    try {
      const text = await extractTextForSimhash(bytes, originalName, mimeType);
      if (text?.trim()) textSimhash = textSimhash64(text);
    } catch (err) {
      console.error("[certify] textSimhash failed", err);
    }
  }

  try {
    if (isCertifiableImage(mimeType, originalName)) {
      return await certifyImage(
        file,
        originalName,
        mimeType,
        options,
        versionMeta,
        inputSha256,
      );
    }
    return await certifyGeneric(
      file,
      originalName,
      mimeType,
      options,
      versionMeta,
      inputSha256,
      textSimhash,
    );
  } catch (err) {
    if (err instanceof ExactMatchRace) {
      const view = publicCertificateView(err.certificate);
      return alreadyCertifiedOutcome({
        kind: "EXACT",
        certificate: view,
        matchedOn:
          err.certificate.sha256 === inputSha256
            ? "sha256"
            : "inputSha256",
        revokedAt: err.certificate.revokedAt?.toISOString() ?? null,
        revokeReason: err.certificate.revokeReason,
      });
    }
    throw err;
  }
}

export async function getCertificateById(
  certId: string,
): Promise<Certificate | null> {
  const normalized = normalizeCertId(certId);
  if (!normalized) return null;
  return prisma.certificate.findUnique({ where: { certId: normalized } });
}

/** Lookup by 8-char watermark token (prefix of compact certId, or legacy ID). */
export async function getCertificateByWatermarkToken(
  token: string,
): Promise<Certificate | null> {
  const t = token.replace(/\0/g, "").trim().toUpperCase();
  if (!t) return null;
  // Exact legacy match
  const exact = await prisma.certificate.findUnique({ where: { certId: t } });
  if (exact) return exact;
  // New IDs: watermark embeds first 8 chars of compact id
  const matches = await prisma.certificate.findMany({
    where: { certId: { startsWith: t } },
    take: 2,
  });
  if (matches.length === 1) return matches[0]!;
  return null;
}

export async function getCertificateBySha256(
  sha256: string,
): Promise<Certificate | null> {
  return prisma.certificate.findFirst({ where: { sha256 } });
}

/** Find certificate with closest phash (Hamming ≤ maxDist). */
export async function findClosestByPhash(
  phash: string,
  maxDist: number,
): Promise<{ cert: Certificate; distance: number } | null> {
  const candidates = await prisma.certificate.findMany({
    where: { imagePhash: { not: null } },
  });
  let best: { cert: Certificate; distance: number } | null = null;
  for (const cert of candidates) {
    if (!cert.imagePhash) continue;
    const d = hamming(phash, cert.imagePhash);
    if (d <= maxDist && (!best || d < best.distance)) {
      best = { cert, distance: d };
    }
  }
  return best;
}

export async function checkRecordSignature(
  cert: Certificate,
): Promise<boolean> {
  if (cert.keyId) {
    return verifyCertificateSignatureWithKeyId(
      payloadFromCert(cert),
      cert.signature,
      cert.keyId,
    );
  }
  return verifyCertificateSignature(
    payloadFromCert(cert),
    cert.signature,
    getEd25519PublicKeyPem(getConfig().ed25519PrivateKey),
  );
}

export async function assertRecordIntegrity(cert: Certificate): Promise<void> {
  if (!(await checkRecordSignature(cert))) {
    throw new AppError(
      "SIGNATURE_INVALID",
      "Certificate record signature is invalid — the record may have been altered",
      409,
    );
  }
}

export async function openStoredFile(cert: Certificate): Promise<Readable> {
  const storage = getStorage();
  if (!(await storage.exists(cert.storagePath))) {
    throw new AppError("NOT_FOUND", "Stored file is missing", 404);
  }
  return storage.get(cert.storagePath);
}

export async function streamStoredFileToResponse(
  cert: Certificate,
): Promise<Response> {
  await assertRecordIntegrity(cert);
  const stream = await openStoredFile(cert);
  const isImage = Boolean(cert.imagePhash);
  const name = certifiedFilename(cert.originalName, cert.certId, {
    forceExt: isImage ? ".png" : undefined,
  });
  const webStream = Readable.toWeb(stream) as ReadableStream;

  return new Response(webStream, {
    headers: {
      "Content-Type": cert.mimeType || "application/octet-stream",
      "Content-Disposition": `attachment; filename="${name.replace(/"/g, "")}"`,
      "Content-Length": String(cert.sizeBytes),
      "X-Content-SHA256": cert.sha256,
    },
  });
}

/** Identical NOT_FOUND body for unknown / malformed IDs (anti-enumeration). */
export function notFoundCertificateResponse(): Response {
  // Tiny busy-wait to normalize timing vs DB miss
  const start = Date.now();
  while (Date.now() - start < 2) {
    /* spin */
  }
  return Response.json(
    { error: { code: "NOT_FOUND", message: "Certificate not found" } },
    { status: 404 },
  );
}

/** Re-hash a File for verification (streaming). */
export async function hashUploadedFile(file: File) {
  if (file.size === 0) {
    throw new AppError("EMPTY_FILE", "Empty files are not allowed", 400);
  }
  if (file.size > getConfig().maxUploadBytes) {
    throw new AppError(
      "FILE_TOO_LARGE",
      `File exceeds maximum size of ${getConfig().maxUploadBytes / (1024 * 1024)} MB`,
      413,
    );
  }
  const nodeStream = Readable.fromWeb(
    file.stream() as import("stream/web").ReadableStream,
  );
  return hashStream(nodeStream);
}

export async function readStoredFileBuffer(cert: Certificate): Promise<Buffer> {
  const stream = await openStoredFile(cert);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/** Hash raw bytes (for in-memory watermarked buffers). */
export function sha256Hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}
