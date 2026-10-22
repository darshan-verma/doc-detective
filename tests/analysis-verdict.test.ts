import { describe, expect, it } from "vitest";
import { deriveVerdict, unavailableResult } from "../src/lib/analysis/verdict";
import { Verdict } from "../src/lib/analysis/types";
import { TextAnalyzer } from "../src/lib/analysis/text";
import { runAnalyzer } from "../src/lib/analysis/runner";

describe("verdict rules", () => {
  it("exact sha256 → AUTHENTIC", () => {
    const r = deriveVerdict({
      originalSha256: "abc",
      uploadedSha256: "abc",
      checks: [],
      contentCheckNames: ["text"],
      formatCheckNames: ["metadata"],
      notChecked: [],
    });
    expect(r.verdict).toBe(Verdict.AUTHENTIC);
  });

  it("FAILED content check → TAMPERED", () => {
    const r = deriveVerdict({
      originalSha256: "a",
      uploadedSha256: "b",
      checks: [
        { name: "text", status: "FAILED" },
        { name: "metadata", status: "PASSED" },
      ],
      contentCheckNames: ["text"],
      formatCheckNames: ["metadata"],
      notChecked: [],
    });
    expect(r.verdict).toBe(Verdict.TAMPERED);
  });

  it("only format FAILED with content PASSED → MODIFIED_FORMAT_ONLY", () => {
    const r = deriveVerdict({
      originalSha256: "a",
      uploadedSha256: "b",
      checks: [
        { name: "text", status: "PASSED" },
        { name: "metadata", status: "FAILED" },
      ],
      contentCheckNames: ["text"],
      formatCheckNames: ["metadata"],
      notChecked: [],
    });
    expect(r.verdict).toBe(Verdict.MODIFIED_FORMAT_ONLY);
  });

  it("required content missing → never AUTHENTIC", () => {
    const r = deriveVerdict({
      originalSha256: "a",
      uploadedSha256: "b",
      checks: [{ name: "text", status: "NOT_CHECKED" }],
      contentCheckNames: ["text"],
      formatCheckNames: [],
      notChecked: ["text"],
      requiredContentMissing: true,
    });
    expect(r.verdict).not.toBe(Verdict.AUTHENTIC);
    expect(r.verdict).toBe(Verdict.ANALYSIS_UNAVAILABLE);
  });

  it("unavailableResult never yields AUTHENTIC", () => {
    const r = unavailableResult("boom", ["full analysis"]);
    expect(r.verdict).toBe(Verdict.ANALYSIS_UNAVAILABLE);
  });
});

describe("analyzer runner", () => {
  it("timeout yields ANALYSIS_UNAVAILABLE", async () => {
    const slow: import("../src/lib/analysis/types").Analyzer = {
      supports: () => true,
      analyze: async () => {
        await new Promise((r) => setTimeout(r, 500));
        return {
          verdict: Verdict.AUTHENTIC,
          confidence: "HIGH",
          checks: [],
          changes: [],
          notChecked: [],
        };
      },
    };
    const result = await runAnalyzer(
      slow,
      Buffer.from("a"),
      Buffer.from("b"),
      50,
    );
    expect(result.verdict).toBe(Verdict.ANALYSIS_UNAVAILABLE);
  });

  it("failed extraction never yields AUTHENTIC", async () => {
    const analyzer = new TextAnalyzer();
    const result = await analyzer.analyze(
      Buffer.from("hello"),
      Buffer.from("hello\nworld"),
    );
    expect(result.verdict).toBe(Verdict.TAMPERED);
    expect(result.verdict).not.toBe(Verdict.AUTHENTIC);
  });
});
