/**
 * Upgrade v1 certificate signatures to v2 after verifying stored bytes and
 * recomputing analysis fields. Never re-signs from untrusted DB values alone.
 *
 * Usage:
 *   npx tsx scripts/resign-v2.ts          # dry-run (default)
 *   npx tsx scripts/resign-v2.ts --apply  # write signatureVersion=2
 */
import { createHash } from "crypto";
import { PrismaClient } from "@prisma/client";
import { getConfig, resetConfigCache } from "../src/lib/config";
import { hashBuffer } from "../src/lib/hashing";
import {
  cellSignatures,
  decodeImage,
  extract,
  isCertifiableImage,
  phash64,
} from "../src/lib/image";
import {
  canonicalJson,
  payloadFromCert,
  resetSigningKeyCache,
  signCertificateRecordV2,
  verifyCertificateSignature,
  verifyCertificateSignatureWithKeyId,
} from "../src/lib/signing";
import { getStorage, LocalDiskStorage, setStorage } from "../src/lib/storage";
import { getSigningProvider } from "../src/lib/trust/keys";

const prisma = new PrismaClient();
const apply = process.argv.includes("--apply");

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b);
}

async function readStored(path: string): Promise<Buffer> {
  const stream = await getStorage().get(path);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function verifyV1(cert: {
  certId: string;
  sha256: string;
  imagePhash: string | null;
  width: number | null;
  height: number | null;
  createdAt: Date;
  signature: string;
  keyId: string;
}): Promise<boolean> {
  const payload = payloadFromCert(cert);
  if (cert.keyId) {
    return verifyCertificateSignatureWithKeyId(
      payload,
      cert.signature,
      cert.keyId,
    );
  }
  return verifyCertificateSignature(payload, cert.signature);
}

async function main() {
  resetConfigCache();
  resetSigningKeyCache();
  if (!process.env.STORAGE_DIR) {
    process.env.STORAGE_DIR = getConfig().storageDir;
  }
  setStorage(new LocalDiskStorage(getConfig().storageDir));

  const all = await prisma.certificate.findMany({
    orderBy: { createdAt: "asc" },
  });
  const v1 = all.filter((c) => (c.signatureVersion ?? 1) < 2);

  const report: Array<{ certId: string; status: string; reason?: string }> = [];

  for (const cert of v1) {
    try {
      const v1Ok = await verifyV1(cert);
      if (!v1Ok) {
        report.push({
          certId: cert.certId,
          status: "skipped",
          reason: "v1 signature invalid",
        });
        continue;
      }

      let bytes: Buffer;
      try {
        bytes = await readStored(cert.storagePath);
      } catch {
        report.push({
          certId: cert.certId,
          status: "skipped",
          reason: "stored file missing",
        });
        continue;
      }

      if (sha256Hex(bytes) !== cert.sha256) {
        report.push({
          certId: cert.certId,
          status: "skipped",
          reason: "stored sha256 mismatch",
        });
        continue;
      }

      const hashed = await hashBuffer(bytes);
      let storedChunks: string[] = [];
      try {
        storedChunks = JSON.parse(cert.chunkHashes) as string[];
      } catch {
        report.push({
          certId: cert.certId,
          status: "skipped",
          reason: "chunkHashes not parseable",
        });
        continue;
      }
      if (!deepEqual(hashed.chunkHashes, storedChunks)) {
        report.push({
          certId: cert.certId,
          status: "skipped",
          reason: "recomputed chunkHashes differ",
        });
        continue;
      }

      const isImage =
        Boolean(cert.imagePhash) ||
        isCertifiableImage(cert.mimeType, cert.originalName);

      if (isImage && cert.imagePhash) {
        let pixels;
        try {
          pixels = await decodeImage(bytes);
        } catch {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "image decode failed",
          });
          continue;
        }

        if (pixels.width !== cert.width || pixels.height !== cert.height) {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "recomputed dimensions differ",
          });
          continue;
        }

        const phash = phash64(pixels);
        if (phash !== cert.imagePhash) {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "recomputed imagePhash differs",
          });
          continue;
        }

        const gridSize = cert.gridSize || getConfig().imageGridSize;
        const cells = cellSignatures(pixels, gridSize);
        let storedCells: unknown = null;
        try {
          storedCells = cert.cellSignatures
            ? JSON.parse(cert.cellSignatures)
            : null;
        } catch {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "cellSignatures not parseable",
          });
          continue;
        }
        if (!deepEqual(cells, storedCells)) {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "recomputed cellSignatures differ",
          });
          continue;
        }

        const config = getConfig();
        const extracted = extract(pixels, {
          key: config.watermarkKey,
          step: config.watermarkQimStep,
        });
        let storedBits: unknown = null;
        try {
          storedBits = cert.watermarkBits
            ? JSON.parse(cert.watermarkBits)
            : null;
        } catch {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "watermarkBits not parseable",
          });
          continue;
        }
        if (
          storedBits != null &&
          !deepEqual(extracted.payloadBits, storedBits)
        ) {
          report.push({
            certId: cert.certId,
            status: "skipped",
            reason: "re-extracted watermarkBits differ",
          });
          continue;
        }
      }

      const signed = await signCertificateRecordV2({
        certId: cert.certId,
        sha256: cert.sha256,
        inputSha256: cert.inputSha256,
        sizeBytes: cert.sizeBytes,
        mimeType: cert.mimeType,
        createdAt: cert.createdAt,
        keyId: cert.keyId || (await getSigningProvider().getActiveKeyId()),
        parentCertId: cert.parentCertId,
        version: cert.version,
        similarToCertId: cert.similarToCertId,
        chunkHashes: storedChunks,
        imagePhash: cert.imagePhash,
        width: cert.width,
        height: cert.height,
        gridSize: cert.gridSize,
        cellSignatures: cert.cellSignatures
          ? JSON.parse(cert.cellSignatures)
          : null,
        watermarkBits: cert.watermarkBits
          ? JSON.parse(cert.watermarkBits)
          : null,
        watermarkVersion: cert.watermarkVersion,
        textSimhash: cert.textSimhash,
      });

      if (apply) {
        await prisma.certificate.update({
          where: { id: cert.id },
          data: {
            signature: signed.signature,
            signatureAlg: signed.alg,
            keyId: signed.keyId,
            signatureVersion: 2,
          },
        });
        report.push({ certId: cert.certId, status: "upgraded" });
      } else {
        report.push({
          certId: cert.certId,
          status: "would-upgrade",
          reason: "dry-run",
        });
      }
    } catch (err) {
      report.push({
        certId: cert.certId,
        status: "skipped",
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const upgraded = report.filter(
    (r) => r.status === "upgraded" || r.status === "would-upgrade",
  ).length;
  const skipped = report.filter((r) => r.status === "skipped").length;
  console.log(
    JSON.stringify(
      {
        mode: apply ? "apply" : "dry-run",
        considered: v1.length,
        upgraded,
        skipped,
        report,
      },
      null,
      2,
    ),
  );

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
