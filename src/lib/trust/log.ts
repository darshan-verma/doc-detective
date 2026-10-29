import { createHash } from "crypto";
import type { LogEntry, Prisma } from "@prisma/client";
import { prisma } from "../prisma";

/** Fixed genesis prevHash for the first log entry. */
export const GENESIS_PREV_HASH = createHash("sha256")
  .update("doc-detective-log-genesis-v1")
  .digest("hex");

export type LogEventType =
  | "CERTIFICATE_CREATED"
  | "CERTIFICATE_REVOKED"
  | "KEY_ROTATION";

export interface AppendLogInput {
  certId?: string | null;
  eventType: LogEventType;
  /** Precomputed content hash for the record being logged. */
  recordHash: string;
  createdAt?: Date;
  /** Optional JSON-serializable metadata (e.g. similarToCertId link). */
  details?: Record<string, unknown> | null;
}

type DbClient = Prisma.TransactionClient | typeof prisma;

export function computeEntryHash(parts: {
  seq: number;
  prevHash: string;
  recordHash: string;
  createdAt: Date;
}): string {
  const iso = parts.createdAt.toISOString();
  return createHash("sha256")
    .update(`${parts.seq}|${parts.prevHash}|${parts.recordHash}|${iso}`)
    .digest("hex");
}

export function hashCertificateRecord(fields: {
  certId: string;
  sha256: string;
  sizeBytes: number;
  keyId: string;
  signature: string;
  createdAt: Date | string;
}): string {
  const createdAt =
    fields.createdAt instanceof Date
      ? fields.createdAt.toISOString()
      : new Date(fields.createdAt).toISOString();
  return createHash("sha256")
    .update(
      `${fields.certId}|${fields.sha256}|${fields.sizeBytes}|${fields.keyId}|${fields.signature}|${createdAt}`,
    )
    .digest("hex");
}

/** Domain-separated hash bound to the revocation event itself (not the creation record). */
export function hashRevokeRecord(fields: {
  certId: string;
  revokedAt: Date | string;
  reason: string;
}): string {
  const revokedAt =
    fields.revokedAt instanceof Date
      ? fields.revokedAt.toISOString()
      : new Date(fields.revokedAt).toISOString();
  const reasonHash = createHash("sha256")
    .update(fields.reason, "utf8")
    .digest("hex");
  return createHash("sha256")
    .update(`doc-detective/revoke/v1\n${fields.certId}|${revokedAt}|${reasonHash}`)
    .digest("hex");
}

export interface RevocationLogCheck {
  revoked: boolean;
  /** True when a valid CERTIFICATE_REVOKED log entry was found. */
  fromLog: boolean;
  /** True when Certificate.revokedAt is set. */
  fromColumn: boolean;
}

/**
 * Revocation status from the transparency log (primary) and column (secondary).
 * A cert is revoked if a CERTIFICATE_REVOKED entry has a recomputed entryHash
 * and a recordHash matching hashRevokeRecord for that event.
 */
export async function checkCertificateRevocation(cert: {
  certId: string;
  revokedAt: Date | null;
  revokeReason: string | null;
}): Promise<RevocationLogCheck> {
  const fromColumn = Boolean(cert.revokedAt);
  const entries = await prisma.logEntry.findMany({
    where: { certId: cert.certId, eventType: "CERTIFICATE_REVOKED" },
    orderBy: { seq: "asc" },
  });

  let fromLog = false;
  for (const entry of entries) {
    const recomputed = computeEntryHash({
      seq: entry.seq,
      prevHash: entry.prevHash,
      recordHash: entry.recordHash,
      createdAt: entry.createdAt,
    });
    if (recomputed !== entry.entryHash) continue;

    let revokedAt: Date | null = null;
    let reason = "";
    if (entry.details) {
      try {
        const d = JSON.parse(entry.details) as {
          revokedAt?: string;
          reason?: string;
        };
        if (d.revokedAt) revokedAt = new Date(d.revokedAt);
        reason = d.reason ?? "";
      } catch {
        /* fall through */
      }
    }
    if (!revokedAt && cert.revokedAt) {
      revokedAt = cert.revokedAt;
      reason = cert.revokeReason ?? "";
    }
    if (!revokedAt) continue;

    const expected = hashRevokeRecord({
      certId: cert.certId,
      revokedAt,
      reason,
    });
    if (expected === entry.recordHash) {
      fromLog = true;
      break;
    }
  }

  if (fromLog !== fromColumn) {
    console.error(
      "[revoke] column and transparency log disagree",
      {
        certId: cert.certId,
        fromLog,
        fromColumn,
        revokedAt: cert.revokedAt?.toISOString() ?? null,
      },
    );
  }

  return {
    revoked: fromLog || fromColumn,
    fromLog,
    fromColumn,
  };
}

async function appendInside(
  tx: Prisma.TransactionClient,
  input: AppendLogInput,
): Promise<LogEntry> {
  const last = await tx.logEntry.findFirst({
    orderBy: { seq: "desc" },
  });
  const seq = (last?.seq ?? 0) + 1;
  const prevHash = last?.entryHash ?? GENESIS_PREV_HASH;
  const createdAt = input.createdAt ?? new Date();
  const entryHash = computeEntryHash({
    seq,
    prevHash,
    recordHash: input.recordHash,
    createdAt,
  });
  return tx.logEntry.create({
    data: {
      seq,
      certId: input.certId ?? null,
      eventType: input.eventType,
      recordHash: input.recordHash,
      prevHash,
      entryHash,
      details: input.details ? JSON.stringify(input.details) : null,
      createdAt,
    },
  });
}

/**
 * Append a single entry. When called outside a transaction, wraps itself in
 * one so seq/prevHash never fork. Pass an existing TransactionClient to
 * compose with certificate creation.
 */
export async function appendLogEntry(
  input: AppendLogInput,
  client?: Prisma.TransactionClient,
): Promise<LogEntry> {
  if (client) {
    return appendInside(client, input);
  }
  return prisma.$transaction((tx) => appendInside(tx, input));
}

export interface ChainVerifyResult {
  ok: boolean;
  checkedFrom: number;
  checkedTo: number;
  /** First broken sequence number, if any. */
  brokenAt: number | null;
  reason?: string;
}

export async function verifyLogChain(
  fromSeq?: number,
  toSeq?: number,
): Promise<ChainVerifyResult> {
  const where: Prisma.LogEntryWhereInput = {};
  if (fromSeq != null || toSeq != null) {
    where.seq = {};
    if (fromSeq != null) where.seq.gte = fromSeq;
    if (toSeq != null) where.seq.lte = toSeq;
  }

  const entries = await prisma.logEntry.findMany({
    where,
    orderBy: { seq: "asc" },
  });

  if (entries.length === 0) {
    return {
      ok: true,
      checkedFrom: fromSeq ?? 0,
      checkedTo: toSeq ?? 0,
      brokenAt: null,
      reason: "no entries in range",
    };
  }

  const checkedFrom = entries[0]!.seq;
  const checkedTo = entries[entries.length - 1]!.seq;

  let expectedPrev = GENESIS_PREV_HASH;
  if (checkedFrom > 1) {
    const prior = await prisma.logEntry.findUnique({
      where: { seq: checkedFrom - 1 },
    });
    if (!prior) {
      return {
        ok: false,
        checkedFrom,
        checkedTo,
        brokenAt: checkedFrom,
        reason: `missing predecessor seq ${checkedFrom - 1}`,
      };
    }
    expectedPrev = prior.entryHash;
  }

  for (const entry of entries) {
    if (entry.prevHash !== expectedPrev) {
      return {
        ok: false,
        checkedFrom,
        checkedTo,
        brokenAt: entry.seq,
        reason: "prevHash mismatch",
      };
    }
    const recomputed = computeEntryHash({
      seq: entry.seq,
      prevHash: entry.prevHash,
      recordHash: entry.recordHash,
      createdAt: entry.createdAt,
    });
    if (recomputed !== entry.entryHash) {
      return {
        ok: false,
        checkedFrom,
        checkedTo,
        brokenAt: entry.seq,
        reason: "entryHash mismatch",
      };
    }
    expectedPrev = entry.entryHash;
  }

  return { ok: true, checkedFrom, checkedTo, brokenAt: null };
}

/** @internal unused type guard helper for DbClient */
export type { DbClient };
