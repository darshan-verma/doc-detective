import { createHash } from "crypto";
import type { Checkpoint } from "@prisma/client";
import { prisma } from "../../prisma";
import {
  buildMerkleTree,
  getInclusionProof,
  type MerkleInclusionProof,
} from "../merkle";
import {
  buildTimeStampRequest,
  defaultTsaClient,
  merkleRootMessageImprint,
  verifyTimeStampResponse,
  type TsaClient,
} from "./rfc3161";

export const DEFAULT_TSA_URL =
  process.env.TSA_URL ?? "https://freetsa.org/tsr";

function checkpointIntervalEntries(): number {
  return Math.max(
    1,
    Number(process.env.CHECKPOINT_EVERY_N_ENTRIES ?? 10),
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function hashCheckpoint(cp: {
  fromSeq: number;
  toSeq: number;
  merkleRoot: string;
  previousCheckpointHash: string;
}): string {
  return createHash("sha256")
    .update(
      `${cp.fromSeq}|${cp.toSeq}|${cp.merkleRoot}|${cp.previousCheckpointHash}`,
    )
    .digest("hex");
}

export interface CheckpointJobResult {
  created: boolean;
  checkpoint?: Checkpoint;
  reason?: string;
  retries?: number;
}

/**
 * Build a Merkle tree over entryHashes since the last checkpoint, request an
 * RFC 3161 timestamp, store the Checkpoint, and attach inclusion proofs to
 * certificates whose log entries fall in the range.
 *
 * Never throws for TSA unavailability after retries — returns created:false.
 * Certification must not block on this.
 */
export async function runCheckpointJob(options?: {
  tsaClient?: TsaClient;
  tsaUrl?: string;
  force?: boolean;
  maxRetries?: number;
}): Promise<CheckpointJobResult> {
  const tsaUrl = options?.tsaUrl ?? DEFAULT_TSA_URL;
  const tsaClient = options?.tsaClient ?? defaultTsaClient;
  const maxRetries = options?.maxRetries ?? 3;

  const lastCp = await prisma.checkpoint.findFirst({
    orderBy: { toSeq: "desc" },
  });
  const fromSeq = (lastCp?.toSeq ?? 0) + 1;

  const pending = await prisma.logEntry.findMany({
    where: { seq: { gte: fromSeq } },
    orderBy: { seq: "asc" },
  });

  if (pending.length === 0) {
    return { created: false, reason: "no pending log entries" };
  }

  if (
    !options?.force &&
    pending.length < checkpointIntervalEntries()
  ) {
    return {
      created: false,
      reason: `only ${pending.length} entries (need ${checkpointIntervalEntries()})`,
    };
  }

  const toSeq = pending[pending.length - 1]!.seq;
  const entryHashes = pending.map((e) => e.entryHash);
  const { root: merkleRoot } = buildMerkleTree(entryHashes);
  const previousCheckpointHash = lastCp
    ? hashCheckpoint(lastCp)
    : createHash("sha256").update("doc-detective-checkpoint-genesis").digest("hex");

  const imprint = merkleRootMessageImprint(merkleRoot);
  const tsReq = buildTimeStampRequest(imprint);

  let token: Buffer | null = null;
  let genTime: Date | null = null;
  let lastError = "";
  let retries = 0;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const respDer = await tsaClient(tsReq.der, tsaUrl);
      const verified = verifyTimeStampResponse(respDer, tsReq);
      if (!verified.ok) {
        lastError = verified.reason;
        retries++;
        await sleep(100 * 2 ** attempt);
        continue;
      }
      token = respDer;
      genTime = verified.genTime;
      break;
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      retries++;
      await sleep(100 * 2 ** attempt);
    }
  }

  if (!token) {
    return {
      created: false,
      reason: `TSA unreachable or rejected: ${lastError}`,
      retries,
    };
  }

  const checkpoint = await prisma.$transaction(async (tx) => {
    const cp = await tx.checkpoint.create({
      data: {
        fromSeq,
        toSeq,
        merkleRoot,
        previousCheckpointHash,
        tsaUrl,
        timestampToken: token!,
        genTime,
      },
    });

    // Attach inclusion proofs to certificates referenced by log entries
    for (let i = 0; i < pending.length; i++) {
      const entry = pending[i]!;
      if (!entry.certId || entry.eventType !== "CERTIFICATE_CREATED") continue;
      const proof: MerkleInclusionProof = getInclusionProof(entryHashes, i);
      await tx.certificate.updateMany({
        where: { certId: entry.certId },
        data: {
          checkpointId: cp.id,
          inclusionProof: JSON.stringify(proof),
          timestampStatus: "ANCHORED",
        },
      });
    }

    return cp;
  });

  return { created: true, checkpoint, retries };
}

/** Downloadable proof bundle for offline openssl verification. */
export async function getProofBundle(certId: string): Promise<{
  record: Record<string, unknown>;
  inclusionProof: MerkleInclusionProof | null;
  checkpoint: {
    id: string;
    fromSeq: number;
    toSeq: number;
    merkleRoot: string;
    previousCheckpointHash: string;
    tsaUrl: string;
    genTime: string | null;
    timestampTokenBase64: string;
  } | null;
  logEntry: {
    seq: number;
    entryHash: string;
    recordHash: string;
    prevHash: string;
    createdAt: string;
  } | null;
} | null> {
  const cert = await prisma.certificate.findUnique({ where: { certId } });
  if (!cert) return null;

  const logEntry = await prisma.logEntry.findFirst({
    where: { certId, eventType: "CERTIFICATE_CREATED" },
    orderBy: { seq: "asc" },
  });

  let checkpoint = null;
  if (cert.checkpointId) {
    const cp = await prisma.checkpoint.findUnique({
      where: { id: cert.checkpointId },
    });
    if (cp) {
      checkpoint = {
        id: cp.id,
        fromSeq: cp.fromSeq,
        toSeq: cp.toSeq,
        merkleRoot: cp.merkleRoot,
        previousCheckpointHash: cp.previousCheckpointHash,
        tsaUrl: cp.tsaUrl,
        genTime: cp.genTime?.toISOString() ?? null,
        timestampTokenBase64: Buffer.from(cp.timestampToken).toString("base64"),
      };
    }
  }

  return {
    record: {
      certId: cert.certId,
      sha256: cert.sha256,
      sizeBytes: cert.sizeBytes,
      keyId: cert.keyId,
      signatureAlg: cert.signatureAlg,
      signature: cert.signature,
      timestampStatus: cert.timestampStatus,
      createdAt: cert.createdAt.toISOString(),
    },
    inclusionProof: cert.inclusionProof
      ? (JSON.parse(cert.inclusionProof) as MerkleInclusionProof)
      : null,
    checkpoint,
    logEntry: logEntry
      ? {
          seq: logEntry.seq,
          entryHash: logEntry.entryHash,
          recordHash: logEntry.recordHash,
          prevHash: logEntry.prevHash,
          createdAt: logEntry.createdAt.toISOString(),
        }
      : null,
  };
}
