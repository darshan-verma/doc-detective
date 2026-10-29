import { describe, expect, it } from "vitest";
import { Verdict } from "../src/lib/analysis/types";
import { explainAnalysis, bannerTone } from "../src/lib/explain";

describe("explainAnalysis", () => {
  it("AUTHENTIC disclaimer confirms unchanged bytes", () => {
    const plain = explainAnalysis({
      verdict: Verdict.AUTHENTIC,
      confidence: "HIGH",
      checks: [{ name: "sha256", status: "PASSED" }],
      changes: [],
      notChecked: [],
    });
    expect(plain.disclaimer).toMatch(/unchanged since it was certified/i);
    expect(plain.disclaimer).toMatch(/not that its original contents are true/i);
  });

  it("MODIFIED_FORMAT_ONLY disclaimer says re-saved", () => {
    const plain = explainAnalysis({
      verdict: Verdict.MODIFIED_FORMAT_ONLY,
      confidence: "MEDIUM",
      checks: [{ name: "file-properties", status: "FAILED" }],
      changes: [],
      notChecked: [],
    });
    expect(plain.disclaimer).toMatch(/visible content matches/i);
    expect(plain.disclaimer).toMatch(/re-saved/i);
    expect(plain.disclaimer).not.toMatch(/unchanged since it was certified/i);
  });

  it("TAMPERED and ANALYSIS_UNAVAILABLE have no unchanged disclaimer", () => {
    for (const verdict of [
      Verdict.TAMPERED,
      Verdict.ANALYSIS_UNAVAILABLE,
      Verdict.NOT_FOUND,
    ]) {
      const plain = explainAnalysis({
        verdict,
        confidence: "HIGH",
        checks: [{ name: "text", status: "FAILED" }],
        changes: [],
        notChecked: [],
      });
      expect(plain.disclaimer).toBe("");
      expect(plain.disclaimer).not.toMatch(/unchanged/i);
    }
  });

  it("REVOKED has no unchanged disclaimer", () => {
    const plain = explainAnalysis(
      {
        verdict: Verdict.AUTHENTIC,
        confidence: "HIGH",
        checks: [],
        changes: [],
        notChecked: [],
      },
      { revoked: true },
    );
    expect(plain.headline).toBe("REVOKED");
    expect(plain.disclaimer).toBe("");
  });

  for (const verdict of [
    Verdict.AUTHENTIC,
    Verdict.MODIFIED_FORMAT_ONLY,
    Verdict.TAMPERED,
    Verdict.NOT_FOUND,
    Verdict.ANALYSIS_UNAVAILABLE,
  ]) {
    it(`produces explanation for ${verdict}`, () => {
      const plain = explainAnalysis({
        verdict,
        confidence: "HIGH",
        checks: [{ name: "text", status: "PASSED" }],
        changes: [],
        notChecked: ["ocr"],
      });
      expect(plain.headline.length).toBeGreaterThan(0);
      expect(plain.explanation.length).toBeGreaterThan(10);
      expect(plain.whatWeCouldNotCheck).toContain("ocr");
    });
  }

  it("maps banner tones", () => {
    expect(bannerTone(Verdict.AUTHENTIC)).toBe("green");
    expect(bannerTone(Verdict.MODIFIED_FORMAT_ONLY)).toBe("amber");
    expect(bannerTone(Verdict.TAMPERED)).toBe("red");
    expect(bannerTone(Verdict.NOT_FOUND)).toBe("grey");
  });

  it("TAMPERED headline/confidence come from content checks", () => {
    const plain = explainAnalysis({
      verdict: Verdict.TAMPERED,
      confidence: "HIGH",
      checks: [
        { name: "text", status: "FAILED", detail: "diff" },
        { name: "visual", status: "FAILED", detail: "pixels" },
        { name: "file-properties", status: "FAILED", detail: "Producer changed" },
      ],
      changes: [
        { location: "page 1", description: "Text content differs", kind: "text" },
        {
          location: "page 1",
          description: "Visual differ 2.00% pixels",
          kind: "visual",
        },
      ],
      formatDifferences: [
        { description: 'Producer: "A" → "B"', kind: "metadata" },
      ],
      notChecked: [],
    });
    expect(plain.explanation.toLowerCase()).toMatch(/text/);
    expect(plain.explanation.toLowerCase()).toMatch(/appearance/);
    expect(plain.confidenceBadge.reason).toMatch(/text and appearance/i);
    expect(plain.formatDifferences).toHaveLength(1);
    expect(plain.whatWeChecked[0]?.label).toBe("Text");
    expect(plain.disclaimer).toBe("");
  });
});
