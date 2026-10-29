import { describe, expect, it, vi } from "vitest";
import {
  LogHeadConflict,
  isRetryableTxError,
  withTxRetry,
} from "../src/lib/trust/tx-retry";

function prismaErr(
  code: string,
  extra: Record<string, unknown> = {},
): Error & Record<string, unknown> {
  const err = new Error(`${code}`) as Error & Record<string, unknown>;
  err.code = code;
  Object.assign(err, extra);
  return err;
}

describe("isRetryableTxError", () => {
  it("retries LogHeadConflict, P2034, LogEntry.seq P2002, and transient labels", () => {
    expect(isRetryableTxError(new LogHeadConflict())).toBe(true);
    expect(isRetryableTxError(prismaErr("P2034"))).toBe(true);
    expect(
      isRetryableTxError(prismaErr("P2002", { meta: { target: ["seq"] } })),
    ).toBe(true);
    expect(
      isRetryableTxError(
        prismaErr("P2002", { meta: { target: ["LogEntry.seq"] } }),
      ),
    ).toBe(true);
    expect(
      isRetryableTxError(
        prismaErr("UNKNOWN", {
          errorLabels: ["TransientTransactionError"],
        }),
      ),
    ).toBe(true);
    expect(
      isRetryableTxError(
        new Error(
          "Transaction failed due to a write conflict or a deadlock. Please retry your transaction",
        ),
      ),
    ).toBe(true);
  });

  it("does not retry Certificate hash P2002 or unrelated errors", () => {
    expect(
      isRetryableTxError(
        prismaErr("P2002", { meta: { target: ["sha256"] } }),
      ),
    ).toBe(false);
    expect(
      isRetryableTxError(
        prismaErr("P2002", { meta: { target: ["inputSha256"] } }),
      ),
    ).toBe(false);
    expect(isRetryableTxError(new Error("boom"))).toBe(false);
    expect(isRetryableTxError(prismaErr("P2003"))).toBe(false);
  });
});

describe("withTxRetry", () => {
  it("retries listed errors then succeeds", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new LogHeadConflict())
      .mockRejectedValueOnce(prismaErr("P2034"))
      .mockRejectedValueOnce(
        prismaErr("P2002", { meta: { target: ["seq"] } }),
      )
      .mockResolvedValueOnce("ok");

    await expect(
      withTxRetry(fn, { attempts: 5, baseMs: 1, jitter: false }),
    ).resolves.toBe("ok");
    expect(fn).toHaveBeenCalledTimes(4);
  });

  it("gives up after N attempts", async () => {
    const fn = vi.fn().mockRejectedValue(new LogHeadConflict("still racing"));
    await expect(
      withTxRetry(fn, { attempts: 3, baseMs: 1, jitter: false }),
    ).rejects.toBeInstanceOf(LogHeadConflict);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("does not retry non-retryable errors", async () => {
    const fn = vi.fn().mockRejectedValue(new Error("permanent"));
    await expect(
      withTxRetry(fn, { attempts: 5, baseMs: 1, jitter: false }),
    ).rejects.toThrow("permanent");
    expect(fn).toHaveBeenCalledTimes(1);
  });
});
