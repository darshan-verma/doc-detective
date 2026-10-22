import { describe, expect, it } from "vitest";
import { normalizeText } from "../src/lib/diff/normalize";

describe("normalizeText", () => {
  it("NFKC-normalizes and collapses Unicode whitespace including NBSP", () => {
    expect(normalizeText("a\u00A0\u00A0b")).toBe("a b");
    expect(normalizeText("  hello   world  ")).toBe("hello world");
  });

  it("strips bullet and control glyphs", () => {
    expect(normalizeText("• item\u0001")).toBe("item");
  });
});
