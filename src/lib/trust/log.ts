import { createHash } from "crypto";
import type { LogEntry, Prisma } from "@prisma/client";
import { prisma } from "../prisma";

/** Fixed genesis prevHash for the first log entry. */
export const GENESIS_PREV_HASH = createHash("sha256")
  .update("doc-detective-log-genesis-v1")
  .digest("hex");

/** Domain-separated prefix for log entry hash v2. */
export const LOG_ENTRY_DOMAIN_V2 = "doc-detective/log/v2\n";

/** Singleton document id for LogChainStatus. */
export const LOG_CHAIN_STATUS_ID = "singleton";

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

export interface EntryHashParts {
  seq: number;
  prevHash: string;
  recordHash: string;
  createdAt: Date;
  /** Defaults to 1 (legacy). New appends use 2. */
  entryVersion?: number;
  certId?: string | null;
  eventType?: string;
  /** Raw details JSON string (or null). */
  details?: string | null;
}

/**
 * Compute entryHash. v1: seq|prevHash|recordHash|createdAt.
 * v2: domain + seq|prevHash|recordHash|createdAt|certId|eventType|sha256(details).
 */
export function computeEntryHash(parts: EntryHashParts): string {
  const version = parts.entryVersion ?? 1;
  const iso = parts.createdAt.toISOString();
  if (version >= 2) {
    const detailsDigest = createHash("sha256")
      .update(parts.details ?? "", "utf8")
      .digest("hex");
    const certId = parts.certId ?? "";
    const eventType = parts.eventType ?? "";
    return createHash("sha256")
      .update(
        `${LOG_ENTRY_DOMAIN_V2}${parts.seq}|${parts.prevHash}|${parts.recordHash}|${iso}|${certId}|${eventType}|${detailsDigest}`,
      )
      .digest("hex");
  }
  return createHash("sha256")
    .update(`${parts.seq}|${parts.prevHash}|${parts.recordHash}|${iso}`)
    .digest("hex");
}

/** Recompute hash for a stored LogEntry row (picks formula by entryVersion). */
export function recomputeStoredEntryHash(
  entry: Pick<
    LogEntry,
    | "seq"
    | "prevHash"
    | "recordHash"
    | "createdAt"
    | "entryVersion"
    | "certId"
    | "eventType"
    | "details"
  >,
): string {
  return computeEntryHash({
    seq: entry.seq,
    prevHash: entry.prevHash,
    recordHash: entry.recordHash,
    createdAt: entry.createdAt,
    entryVersion: entry.entryVersion ?? 1,
    certId: entry.certId,
    eventType: entry.eventType,
    details: entry.details,
  });
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
  /**
   * True when displayed reason/time are bound (v2 details in entryHash, or
   * v1 recordHash matches reconstructed revoke hash).
   */
  detailsVerified: boolean;
}

function parseRevokeDetails(details: string | null): {
  revokedAt: Date | null;
  reason: string;
} {
  if (!details) return { revokedAt: null, reason: "" };
  try {
    const d = JSON.parse(details) as { revokedAt?: string; reason?: string };
    return {
      revokedAt: d.revokedAt ? new Date(d.revokedAt) : null,
      reason: d.reason ?? "",
    };
  } catch {
    return { revokedAt: null, reason: "" };
  }
}

type RevokeLogEntry = Pick<
  LogEntry,
  | "seq"
  | "prevHash"
  | "recordHash"
  | "createdAt"
  | "entryVersion"
  | "certId"
  | "eventType"
  | "details"
  | "entryHash"
>;

/**
 * Pure revocation decision from already-fetched CERTIFICATE_REVOKED entries.
 * A cert is REVOKED if any entry has a valid entryHash — details/recordHash
 * mismatch only affects detailsVerified, not revoked.
 */
export function evaluateRevocationFromEntries(
  cert: {
    certId: string;
    revokedAt: Date | null;
    revokeReason: string | null;
  },
  entries: RevokeLogEntry[],
): RevocationLogCheck & { chainCheckFromSeq: number | null } {
  const fromColumn = Boolean(cert.revokedAt);
  let fromLog = false;
  let detailsVerified = false;
  let chainCheckFromSeq: number | null = null;

  for (const entry of entries) {
    const recomputed = recomputeStoredEntryHash(entry);
    if (recomputed !== entry.entryHash) continue;

    fromLog = true;
    chainCheckFromSeq = entry.seq;

    const entryVersion = entry.entryVersion ?? 1;
    if (entryVersion >= 2) {
      detailsVerified = true;
    } else {
      const parsed = parseRevokeDetails(entry.details);
      let revokedAt = parsed.revokedAt;
      let reason = parsed.reason;
      if (!revokedAt && cert.revokedAt) {
        revokedAt = cert.revokedAt;
        reason = cert.revokeReason ?? "";
      }
      if (revokedAt) {
        const expected = hashRevokeRecord({
          certId: cert.certId,
          revokedAt,
          reason,
        });
        detailsVerified = expected === entry.recordHash;
      }
    }
    break;
  }

  if (fromLog !== fromColumn) {
    console.error("[revoke] column and transparency log disagree", {
      certId: cert.certId,
      fromLog,
      fromColumn,
      revokedAt: cert.revokedAt?.toISOString() ?? null,
    });
  }

  if (fromLog && !detailsVerified) {
    console.error("[revoke] revocation details could not be verified", {
      certId: cert.certId,
    });
  }

  return {
    revoked: fromLog || fromColumn,
    fromLog,
    fromColumn,
    detailsVerified: fromLog ? detailsVerified : fromColumn,
    chainCheckFromSeq,
  };
}

/**
 * Revocation status from the transparency log (primary) and column (secondary).
 */
export async function checkCertificateRevocation(cert: {
  certId: string;
  revokedAt: Date | null;
  revokeReason: string | null;
}): Promise<RevocationLogCheck> {
  const entries = await prisma.logEntry.findMany({
    where: { certId: cert.certId, eventType: "CERTIFICATE_REVOKED" },
    orderBy: { seq: "asc" },
  });

  const evaluated = evaluateRevocationFromEntries(cert, entries);
  const { chainCheckFromSeq, ...check } = evaluated;

  if (chainCheckFromSeq != null) {
    const latestCp = await prisma.checkpoint.findFirst({
      orderBy: { toSeq: "desc" },
    });
    if (latestCp && latestCp.toSeq >= chainCheckFromSeq) {
      const chain = await verifyLogChain(chainCheckFromSeq, latestCp.toSeq);
      if (!chain.ok) {
        console.error(
          "[revoke] chain unbroken check failed after revocation entry",
          {
            certId: cert.certId,
            entrySeq: chainCheckFromSeq,
            brokenAt: chain.brokenAt,
            reason: chain.reason,
          },
        );
      }
    }
  }

  return check;
}

/** Human-readable revoke banner text. */
export function revokeDisplayMessage(
  check: RevocationLogCheck,
  columnReason?: string | null,
): string {
  if (!check.revoked) return "";
  if (check.detailsVerified && columnReason) {
    return `REVOKED: ${columnReason}`;
  }
  if (check.detailsVerified) {
    return "REVOKED";
  }
  return "Revoked (reason could not be verified)";
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
  const certId = input.certId ?? null;
  const details = input.details ? JSON.stringify(input.details) : null;
  const entryVersion = 2;
  const entryHash = computeEntryHash({
    seq,
    prevHash,
    recordHash: input.recordHash,
    createdAt,
    entryVersion,
    certId,
    eventType: input.eventType,
    details,
  });
  return tx.logEntry.create({
    data: {
      seq,
      certId,
      eventType: input.eventType,
      recordHash: input.recordHash,
      prevHash,
      entryHash,
      entryVersion,
      details,
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
  verifiedAt?: string;
}

/**
 * Pure chain verification over an ordered entry list.
 * `expectedPrevForFirst` is GENESIS_PREV_HASH when the range starts at seq 1,
 * otherwise the prior entry's entryHash.
 */
export function verifyLogEntries(
  entries: RevokeLogEntry[],
  expectedPrevForFirst: string,
  rangeHint?: { fromSeq?: number; toSeq?: number },
): ChainVerifyResult {
  if (entries.length === 0) {
    return {
      ok: true,
      checkedFrom: rangeHint?.fromSeq ?? 0,
      checkedTo: rangeHint?.toSeq ?? 0,
      brokenAt: null,
      reason: "no entries in range",
    };
  }

  const checkedFrom = entries[0]!.seq;
  const checkedTo = entries[entries.length - 1]!.seq;
  let expectedPrev = expectedPrevForFirst;

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
    const recomputed = recomputeStoredEntryHash(entry);
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
  let expectedPrev = GENESIS_PREV_HASH;
  if (checkedFrom > 1) {
    const prior = await prisma.logEntry.findUnique({
      where: { seq: checkedFrom - 1 },
    });
    if (!prior) {
      return {
        ok: false,
        checkedFrom,
        checkedTo: entries[entries.length - 1]!.seq,
        brokenAt: checkedFrom,
        reason: `missing predecessor seq ${checkedFrom - 1}`,
      };
    }
    expectedPrev = prior.entryHash;
  }

  return verifyLogEntries(entries, expectedPrev, { fromSeq, toSeq });
}

/** Persist a full-chain verification result for the /log UI. */
export async function recordLogChainStatus(
  result: ChainVerifyResult,
): Promise<void> {
  const verifiedAt = new Date();
  await prisma.logChainStatus.upsert({
    where: { id: LOG_CHAIN_STATUS_ID },
    create: {
      id: LOG_CHAIN_STATUS_ID,
      verifiedAt,
      ok: result.ok,
      brokenAt: result.brokenAt,
      checkedFrom: result.checkedFrom,
      checkedTo: result.checkedTo,
      reason: result.reason ?? null,
    },
    update: {
      verifiedAt,
      ok: result.ok,
      brokenAt: result.brokenAt,
      checkedFrom: result.checkedFrom,
      checkedTo: result.checkedTo,
      reason: result.reason ?? null,
    },
  });
}

/** Run full verifyLogChain and store the result (used by checkpoint cron). */
export async function verifyAndRecordLogChain(): Promise<ChainVerifyResult> {
  const result = await verifyLogChain();
  await recordLogChainStatus(result);
  return { ...result, verifiedAt: new Date().toISOString() };
}

export async function getLogChainStatus(): Promise<{
  verifiedAt: string;
  ok: boolean;
  brokenAt: number | null;
  checkedFrom: number;
  checkedTo: number;
  reason: string | null;
} | null> {
  const row = await prisma.logChainStatus.findUnique({
    where: { id: LOG_CHAIN_STATUS_ID },
  });
  if (!row) return null;
  return {
    verifiedAt: row.verifiedAt.toISOString(),
    ok: row.ok,
    brokenAt: row.brokenAt,
    checkedFrom: row.checkedFrom,
    checkedTo: row.checkedTo,
    reason: row.reason,
  };
}

/** @internal unused type guard helper for DbClient */
export type { DbClient };
