/**
 * Pure unit tests for log entry hash v2 and revocation (no DB / no prisma mock).
 */
import { describe, expect, it } from "vitest";
import {
  computeEntryHash,
  evaluateRevocationFromEntries,
  GENESIS_PREV_HASH,
  hashRevokeRecord,
  recomputeStoredEntryHash,
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
    const revokedAt = new Date("2024-07-01T00:00:00.000Z");
    const reason = "ok";
    const recordHash = hashRevokeRecord({
      certId: "CERT1",
      revokedAt,
      reason,
    });
    const details = JSON.stringify({
      revokedAt: revokedAt.toISOString(),
      reason,
    });
    const entry = {
      seq: 1,
      certId: "CERT1",
      eventType: "CERTIFICATE_REVOKED",
      recordHash,
      prevHash: GENESIS_PREV_HASH,
      entryVersion: 2,
      createdAt: revokedAt,
      details,
      entryHash: computeEntryHash({
        seq: 1,
        prevHash: GENESIS_PREV_HASH,
        recordHash,
        createdAt: revokedAt,
        entryVersion: 2,
        certId: "CERT1",
        eventType: "CERTIFICATE_REVOKED",
        details,
      }),
    };

    const result = evaluateRevocationFromEntries(
      { certId: "CERT1", revokedAt: null, revokeReason: null },
      [entry],
    );
    expect(result.revoked).toBe(true);
    expect(result.detailsVerified).toBe(true);
  });
});
