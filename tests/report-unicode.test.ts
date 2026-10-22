import { PDFDocument } from "pdf-lib";
import { describe, expect, it } from "vitest";
import { Verdict } from "../src/lib/analysis/types";
import { buildVerificationReportPdf } from "../src/lib/report";

describe("verification report unicode", () => {
  it("generates when diff text contains U+F0B7, arrows, curly quotes and CJK", async () => {
    const { pdf, sha256 } = await buildVerificationReportPdf({
      certId: "TESTCERT000000000000000001",
      verdict: Verdict.TAMPERED,
      analysis: {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks: [
          {
            name: "text",
            status: "FAILED",
            detail: `Bullet \uF0B7 and arrow → and “quotes” and 漢字`,
          },
        ],
        changes: [
          {
            location: "page 1",
            description: `L12: \uF0B7 Principal → “研究员”`,
            kind: "text",
          },
        ],
        notChecked: [],
      },
      registeredSha256: "aa".repeat(32),
      uploadedSha256: "bb".repeat(32),
      signatureValid: true,
      timestampStatus: "PENDING",
    });

    expect(pdf.subarray(0, 4).toString()).toBe("%PDF");
    expect(sha256).toHaveLength(64);
    const reloaded = await PDFDocument.load(pdf);
    expect(reloaded.getPageCount()).toBeGreaterThanOrEqual(1);
    expect(pdf.length).toBeGreaterThan(1000);
  });

  it("continuing after a failing section still produces a report", async () => {
    const { pdf } = await buildVerificationReportPdf({
      certId: "TESTCERT000000000000000002",
      verdict: Verdict.AUTHENTIC,
      analysis: {
        verdict: Verdict.AUTHENTIC,
        confidence: "HIGH",
        checks: [{ name: "sha256", status: "PASSED", detail: "match" }],
        changes: [],
        notChecked: [],
      },
      registeredSha256: "cc".repeat(32),
      uploadedSha256: "cc".repeat(32),
      _testFailSections: ["checks"],
    });

    expect(pdf.subarray(0, 4).toString()).toBe("%PDF");
    const reloaded = await PDFDocument.load(pdf);
    expect(reloaded.getPageCount()).toBeGreaterThanOrEqual(1);
  });
});
