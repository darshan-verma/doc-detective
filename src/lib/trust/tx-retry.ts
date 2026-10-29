/** Thrown when LogHead compare-and-swap loses to a concurrent append. */
export class LogHeadConflict extends Error {
  constructor(message = "LogHead compare-and-swap failed") {
    super(message);
    this.name = "LogHeadConflict";
  }
}

export interface WithTxRetryOptions {
  attempts?: number;
  baseMs?: number;
  jitter?: boolean;
}

function asRecord(err: unknown): Record<string, unknown> | null {
  if (!err || typeof err !== "object") return null;
  return err as Record<string, unknown>;
}

function collectTargets(err: unknown): string[] {
  const rec = asRecord(err);
  if (!rec) return [];
  const meta = rec.meta;
  if (!meta || typeof meta !== "object") return [];
  const target = (meta as { target?: unknown }).target;
  if (Array.isArray(target)) return target.map(String);
  if (typeof target === "string") return [target];
  return [];
}

/** True when a unique violation is on LogEntry.seq (not Certificate hashes). */
export function isLogEntrySeqUniqueViolation(err: unknown): boolean {
  const rec = asRecord(err);
  if (!rec || rec.code !== "P2002") return false;
  return collectTargets(err).some((t) => {
    const last = t.split(".").pop() ?? t;
    return last === "seq";
  });
}

function hasTransientLabel(err: unknown): boolean {
  const seen = new Set<unknown>();
  let cur: unknown = err;
  while (cur && typeof cur === "object" && !seen.has(cur)) {
    seen.add(cur);
    const rec = cur as Record<string, unknown>;
    const labels = rec.errorLabels;
    if (Array.isArray(labels) && labels.includes("TransientTransactionError")) {
      return true;
    }
    const msg = typeof rec.message === "string" ? rec.message : "";
    if (/TransientTransactionError|write conflict|deadlock/i.test(msg)) {
      return true;
    }
    cur = rec.cause ?? rec.originalError ?? null;
  }
  return false;
}

/** Errors that warrant retrying a certify/revoke / log-append transaction. */
export function isRetryableTxError(err: unknown): boolean {
  if (err instanceof LogHeadConflict) return true;
  const rec = asRecord(err);
  if (!rec) return false;
  if (rec.code === "P2034") return true;
  if (isLogEntrySeqUniqueViolation(err)) return true;
  if (hasTransientLabel(err)) return true;
  return false;
}

function backoffMs(attempt: number, baseMs: number, jitter: boolean): number {
  // Cap so large attempt ceilings (certify bursts) don't sleep for minutes.
  const exp = Math.min(baseMs * 2 ** attempt, 1000);
  if (!jitter) return exp;
  return exp * (0.5 + Math.random());
}

/**
 * Retry a transactional write on LogHead conflicts, LogEntry.seq unique
 * races, Prisma P2034, and Mongo TransientTransactionError labels.
 */
export async function withTxRetry<T>(
  fn: () => Promise<T>,
  opts: WithTxRetryOptions = {},
): Promise<T> {
  // Default 5 matches the public contract; certify/revoke pass a higher
  // attempts ceiling so large concurrent bursts can drain under OCC.
  const attempts = opts.attempts ?? 5;
  const baseMs = opts.baseMs ?? 20;
  const jitter = opts.jitter ?? true;
  let lastErr: unknown;

  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (!isRetryableTxError(err) || i === attempts - 1) {
        throw err;
      }
      await new Promise((r) => setTimeout(r, backoffMs(i, baseMs, jitter)));
    }
  }

  throw lastErr;
}
