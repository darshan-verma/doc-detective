import { describe, expect, it } from "vitest";
import { Verdict } from "../src/lib/analysis/types";
import { explainAnalysis, bannerTone } from "../src/lib/explain";

describe("explainAnalysis", () => {
  const verdicts = [
    Verdict.AUTHENTIC,
    Verdict.MODIFIED_FORMAT_ONLY,
    Verdict.TAMPERED,
    Verdict.NOT_FOUND,
    Verdict.ANALYSIS_UNAVAILABLE,
  ];

  for (const verdict of verdicts) {
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
      expect(plain.disclaimer).toMatch(/not that its original contents are true/i);
    });
  }

  it("shows REVOKED notice", () => {
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
  });

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
  });
});
