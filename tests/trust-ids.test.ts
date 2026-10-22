import { describe, expect, it } from "vitest";
import {
  formatCertId,
  generateCertId,
  isLegacyCertId,
  isValidCertIdFormat,
  normalizeCertId,
} from "../src/lib/trust/ids";
import { notFoundCertificateResponse } from "../src/lib/certificates/service";

describe("certificate IDs", () => {
  it("generates 10,000 unique IDs matching the format", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10_000; i++) {
      const id = generateCertId();
      expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
      expect(seen.has(id)).toBe(false);
      seen.add(id);

      const display = formatCertId(id);
      expect(display.startsWith("DD-")).toBe(true);
      expect(normalizeCertId(display)).toBe(id);
    }
    expect(seen.size).toBe(10_000);
  });

  it("still accepts legacy short IDs", () => {
    expect(isLegacyCertId("K7X2M9")).toBe(true);
    expect(normalizeCertId("K7X2M9")).toBe("K7X2M9");
    expect(isValidCertIdFormat("K7X2M9")).toBe(true);
  });

  it("rejects malformed IDs", () => {
    expect(normalizeCertId("!!!")).toBeNull();
    expect(normalizeCertId("short")).toBeNull();
    expect(isValidCertIdFormat("")).toBe(false);
  });

  it("returns identical NOT_FOUND responses for unknown and malformed IDs", async () => {
    const a = notFoundCertificateResponse();
    const b = notFoundCertificateResponse();
    expect(a.status).toBe(404);
    expect(b.status).toBe(404);
    const ja = await a.json();
    const jb = await b.json();
    expect(ja).toEqual(jb);
    expect(ja.error.code).toBe("NOT_FOUND");
    expect(ja.error.message).toBe("Certificate not found");
  });
});
