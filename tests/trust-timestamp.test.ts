import { randomBytes } from "crypto";
import { describe, expect, it } from "vitest";
import {
  buildMockTimeStampResponse,
  buildTimeStampRequest,
  merkleRootMessageImprint,
  verifyTimeStampResponse,
} from "../src/lib/trust/timestamp/rfc3161";

describe("RFC 3161 timestamp verify", () => {
  it("accepts a mocked TSA response with matching imprint and nonce", () => {
    const imprint = merkleRootMessageImprint("abc123merkle");
    const req = buildTimeStampRequest(imprint, {
      nonce: randomBytes(8),
    });
    const resp = buildMockTimeStampResponse(req);
    const result = verifyTimeStampResponse(resp, req);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.genTime).toBeInstanceOf(Date);
    }
  });

  it("rejects wrong messageImprint", () => {
    const imprint = merkleRootMessageImprint("root-a");
    const req = buildTimeStampRequest(imprint);
    const resp = buildMockTimeStampResponse(req, new Date(), {
      wrongImprint: randomBytes(32),
    });
    const result = verifyTimeStampResponse(resp, req);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/messageImprint/i);
    }
  });

  it("rejects wrong nonce", () => {
    const imprint = merkleRootMessageImprint("root-b");
    const req = buildTimeStampRequest(imprint, { nonce: randomBytes(8) });
    const resp = buildMockTimeStampResponse(req, new Date(), {
      wrongNonce: randomBytes(8),
    });
    const result = verifyTimeStampResponse(resp, req);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/nonce/i);
    }
  });

  it("rejects non-granted status", () => {
    const imprint = merkleRootMessageImprint("root-c");
    const req = buildTimeStampRequest(imprint);
    const resp = buildMockTimeStampResponse(req, new Date(), { status: 2 });
    const result = verifyTimeStampResponse(resp, req);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/status/i);
    }
  });
});
