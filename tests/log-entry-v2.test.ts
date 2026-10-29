/**
 * Pure unit tests for log entry hash v2 and revocation (no DB).
 */
import { describe, expect, it, vi } from "vitest";
import {
  applyLogIntegrityToVerifyResponse,
  assessEntriesIntegrity,
  brokenLogChainMessage,
  computeEntryHash,
  evaluateCertificateLogFromEntries,
  evaluateRevocationFromEntries,
  GENESIS_PREV_HASH,
  hashRevokeRecord,
  recomputeStoredEntryHash,
  revokeDisplayMessage,
  verifyLogEntries,
} from "../src/lib/trust/log";

const createdAt = new Date("2024-06-01T00:00:00.000Z");

describe("computeEntryHash v1 / v2", () => {
  it("v1 entries still verify unchanged (eventType not bound)", () => {
    const hash = computeEntryHash({
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "r1",
      createdAt,
      entryVersion: 1,
    });
    expect(
      recomputeStoredEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash: "r1",
        createdAt,
        entryVersion: 1,
        certId: "A",
        eventType: "CERTIFICATE_REVOKED",
        details: null,
      }),
    ).toBe(hash);
    expect(
      recomputeStoredEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash: "r1",
        createdAt,
        entryVersion: 1,
        certId: "A",
        eventType: "CERTIFICATE_CREATED",
        details: null,
      }),
    ).toBe(hash);
  });

  it("v2 binds eventType, certId, and details", () => {
    const details = JSON.stringify({
      revokedAt: "2024-01-01T00:00:00.000Z",
      reason: "x",
    });
    const hash = computeEntryHash({
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "r1",
      createdAt,
      entryVersion: 2,
      certId: "C1",
      eventType: "CERTIFICATE_REVOKED",
      details,
    });
    expect(
      computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash: "r1",
        createdAt,
        entryVersion: 2,
        certId: "C1",
        eventType: "CERTIFICATE_CREATED",
        details,
      }),
    ).not.toBe(hash);
    expect(
      computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash: "r1",
        createdAt,
        entryVersion: 2,
        certId: "OTHER",
        eventType: "CERTIFICATE_REVOKED",
        details,
      }),
    ).not.toBe(hash);
    expect(
      computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash: "r1",
        createdAt,
        entryVersion: 2,
        certId: "C1",
        eventType: "CERTIFICATE_REVOKED",
        details: JSON.stringify({
          revokedAt: "2024-01-01T00:00:00.000Z",
          reason: "y",
        }),
      }),
    ).not.toBe(hash);
  });
});

describe("verifyLogEntries (pure chain)", () => {
  it("detects v2 entryHash mismatch when eventType, certId or details change", () => {
    const details = JSON.stringify({
      revokedAt: "2024-02-01T00:00:00.000Z",
      reason: "lost",
    });
    const honestHash = computeEntryHash({
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "rh",
      createdAt,
      entryVersion: 2,
      certId: "CX",
      eventType: "CERTIFICATE_REVOKED",
      details,
    });
    const honest = {
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "rh",
      createdAt,
      entryVersion: 2,
      certId: "CX",
      eventType: "CERTIFICATE_REVOKED",
      details,
      entryHash: honestHash,
    };

    expect(
      verifyLogEntries(
        [{ ...honest, eventType: "CERTIFICATE_CREATED" }],
        GENESIS_PREV_HASH,
      ).ok,
    ).toBe(false);
    expect(
      verifyLogEntries([{ ...honest, certId: "OTHER" }], GENESIS_PREV_HASH).ok,
    ).toBe(false);
    expect(
      verifyLogEntries(
        [
          {
            ...honest,
            details: JSON.stringify({
              revokedAt: "2024-02-01T00:00:00.000Z",
              reason: "nope",
            }),
          },
        ],
        GENESIS_PREV_HASH,
      ).ok,
    ).toBe(false);
    expect(verifyLogEntries([honest], GENESIS_PREV_HASH).ok).toBe(true);
  });

  it("v1 entries still verify when unchanged", () => {
    const entryHash = computeEntryHash({
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "r1",
      createdAt,
      entryVersion: 1,
    });
    const entry = {
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "r1",
      createdAt,
      entryVersion: 1,
      certId: "V1",
      eventType: "CERTIFICATE_CREATED",
      details: null,
      entryHash,
    };
    expect(verifyLogEntries([entry], GENESIS_PREV_HASH).ok).toBe(true);
  });
});

function makeValidV2RevokeEntry(opts?: {
  certId?: string;
  reason?: string;
  revokedAt?: Date;
  seq?: number;
}) {
  const certId = opts?.certId ?? "CERT1";
  const reason = opts?.reason ?? "ok";
  const revokedAt = opts?.revokedAt ?? new Date("2024-07-01T00:00:00.000Z");
  const seq = opts?.seq ?? 1;
  const recordHash = hashRevokeRecord({ certId, revokedAt, reason });
  const details = JSON.stringify({
    revokedAt: revokedAt.toISOString(),
    reason,
  });
  const entryHash = computeEntryHash({
    seq,
    prevHash: GENESIS_PREV_HASH,
    recordHash,
    createdAt: revokedAt,
    entryVersion: 2,
    certId,
    eventType: "CERTIFICATE_REVOKED",
    details,
  });
  return {
    seq,
    certId,
    eventType: "CERTIFICATE_REVOKED",
    recordHash,
    prevHash: GENESIS_PREV_HASH,
    entryVersion: 2,
    createdAt: revokedAt,
    details,
    entryHash,
  };
}

describe("evaluateRevocationFromEntries", () => {
  it("column cleared + details edited → still revoked, detailsVerified=false", () => {
    const revokedAt = new Date("2024-06-01T00:00:00.000Z");
    const reason = "original-reason";
    const recordHash = hashRevokeRecord({
      certId: "CERT1",
      revokedAt,
      reason,
    });
    const entry = {
      seq: 1,
      certId: "CERT1",
      eventType: "CERTIFICATE_REVOKED",
      recordHash,
      prevHash: GENESIS_PREV_HASH,
      entryVersion: 1,
      createdAt: revokedAt,
      details: JSON.stringify({
        revokedAt: revokedAt.toISOString(),
        reason: "TAMPERED-REASON",
      }),
      entryHash: computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash,
        createdAt: revokedAt,
        entryVersion: 1,
      }),
    };

    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [entry],
    );
    expect(result.revoked).toBe(true);
    expect(result.fromLog).toBe(true);
    expect(result.fromColumn).toBe(false);
    expect(result.detailsVerified).toBe(false);
  });

  it("column cleared + details null → still revoked", () => {
    const revokedAt = new Date("2024-06-02T00:00:00.000Z");
    const recordHash = hashRevokeRecord({
      certId: "CERT1",
      revokedAt,
      reason: "gone",
    });
    const entry = {
      seq: 1,
      certId: "CERT1",
      eventType: "CERTIFICATE_REVOKED",
      recordHash,
      prevHash: GENESIS_PREV_HASH,
      entryVersion: 1,
      createdAt: revokedAt,
      details: null,
      entryHash: computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash,
        createdAt: revokedAt,
        entryVersion: 1,
      }),
    };

    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [entry],
    );
    expect(result.revoked).toBe(true);
    expect(result.fromLog).toBe(true);
    expect(result.detailsVerified).toBe(false);
  });

  it("v2 entry with valid hash → revoked and detailsVerified", () => {
    const entry = makeValidV2RevokeEntry();
    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [entry],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(true);
    expect(result.entryIntegrity).toBe("OK");
  });

  it("fail closed: v2 details edited → revoked + DAMAGED", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const honest = makeValidV2RevokeEntry();
    const damaged = {
      ...honest,
      details: JSON.stringify({
        revokedAt: honest.createdAt.toISOString(),
        reason: "TAMPERED",
      }),
    };
    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [damaged],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(false);
    expect(result.entryIntegrity).toBe("DAMAGED");
    expect(revokeDisplayMessage(result)).toBe(
      "Revoked (revocation record shows signs of tampering)",
    );
    err.mockRestore();
  });

  it("fail closed: v2 details null → revoked + DAMAGED", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const honest = makeValidV2RevokeEntry();
    const damaged = { ...honest, details: null };
    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [damaged],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(false);
    expect(result.entryIntegrity).toBe("DAMAGED");
    err.mockRestore();
  });

  it("fail closed: entryVersion 2→1 → revoked + DAMAGED", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const honest = makeValidV2RevokeEntry();
    const damaged = { ...honest, entryVersion: 1 };
    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [damaged],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(false);
    expect(result.entryIntegrity).toBe("DAMAGED");
    err.mockRestore();
  });

  it("fail closed: entryHash one char changed → revoked + DAMAGED", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const honest = makeValidV2RevokeEntry();
    const flipped =
      honest.entryHash[0] === "a"
        ? "b" + honest.entryHash.slice(1)
        : "a" + honest.entryHash.slice(1);
    const damaged = { ...honest, entryHash: flipped };
    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [damaged],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(false);
    expect(result.entryIntegrity).toBe("DAMAGED");
    err.mockRestore();
  });

  it("fail closed: recordHash changed → revoked + DAMAGED", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const honest = makeValidV2RevokeEntry();
    const damaged = {
      ...honest,
      recordHash: "0".repeat(honest.recordHash.length),
    };
    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [damaged],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(false);
    expect(result.entryIntegrity).toBe("DAMAGED");
    err.mockRestore();
  });
});

describe("evaluateCertificateLogFromEntries / logIntegrity", () => {
  it("damaged CERTIFICATE_CREATED for cert → logIntegrity DAMAGED", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const createdAt = new Date("2024-05-01T00:00:00.000Z");
    const details = null;
    const honestHash = computeEntryHash({
      seq: 1,
      prevHash: GENESIS_PREV_HASH,
      recordHash: "create-rh",
      createdAt,
      entryVersion: 2,
      certId: "CERT1",
      eventType: "CERTIFICATE_CREATED",
      details,
    });
    const damaged = {
      seq: 1,
      certId: "CERT1",
      eventType: "CERTIFICATE_CREATED",
      recordHash: "create-rh",
      prevHash: GENESIS_PREV_HASH,
      entryVersion: 2,
      createdAt,
      details,
      entryHash:
        honestHash[0] === "a"
          ? "b" + honestHash.slice(1)
          : "a" + honestHash.slice(1),
    };

    expect(assessEntriesIntegrity([damaged])).toBe("DAMAGED");

    const result = evaluateCertificateLogFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [damaged],
    );
    expect(result.revoked).toBe(false);
    expect(result.logIntegrity).toBe("DAMAGED");
    err.mockRestore();
  });

  it("latest LogChainStatus broken → verify result logIntegrity BROKEN, not plain AUTHENTIC", () => {
    const authentic = {
      result: "AUTHENTIC" as const,
      message: "File is authentic. Content hash matches the certified original.",
      analysis: {
        verdict: "AUTHENTIC",
        confidence: "HIGH",
        checks: [],
        changes: [],
        notChecked: [],
      },
    };

    const result = applyLogIntegrityToVerifyResponse(authentic, {
      chainStatus: {
        ok: false,
        brokenAt: 42,
      },
    });

    expect(result.logIntegrity).toBe("BROKEN");
    expect(result.analysis?.confidence).toBe("LOW");
    expect(result.message).toBe(brokenLogChainMessage(42));
    // Not plain AUTHENTIC: annotated with BROKEN + LOW confidence.
    expect(
      result.result === "AUTHENTIC" &&
        result.logIntegrity == null &&
        result.analysis?.confidence === "HIGH",
    ).toBe(false);
    expect(result.logIntegrity === "BROKEN").toBe(true);
    expect(result.analysis?.confidence).not.toBe("HIGH");
  });

  it("cert DAMAGED + chain OK → logIntegrity DAMAGED on verify response", () => {
    const authentic = {
      result: "AUTHENTIC" as const,
      message: "File is authentic.",
      analysis: { confidence: "HIGH" },
    };
    const result = applyLogIntegrityToVerifyResponse(authentic, {
      certLogIntegrity: "DAMAGED",
      chainStatus: { ok: true, brokenAt: null },
    });
    expect(result.logIntegrity).toBe("DAMAGED");
    expect(result.result).toBe("AUTHENTIC");
  });

  it("chain BROKEN wins over cert DAMAGED", () => {
    const authentic = {
      result: "AUTHENTIC" as const,
      message: "File is authentic.",
      analysis: { confidence: "HIGH" },
    };
    const result = applyLogIntegrityToVerifyResponse(authentic, {
      certLogIntegrity: "DAMAGED",
      chainStatus: { ok: false, brokenAt: 7 },
    });
    expect(result.logIntegrity).toBe("BROKEN");
    expect(result.message).toBe(brokenLogChainMessage(7));
  });
});
