import { describe, expect, it } from "vitest";
import {
  replaceUnencodable,
  sanitizeForDisplay,
} from "../src/lib/sanitize";

describe("sanitizeForDisplay", () => {
  it("removes U+F0B7 and keeps normal text", () => {
    const input = `Hello \uF0B7 world`;
    expect(sanitizeForDisplay(input)).toBe("Hello  world");
  });

  it("strips private-use and control chars, keeps newlines and arrows", () => {
    const input = `A\u0000B\nC → D\uF0B7E`;
    expect(sanitizeForDisplay(input)).toBe("AB\nC → DE");
  });

  it("keeps curly quotes and CJK", () => {
    const input = `“你好” — café`;
    expect(sanitizeForDisplay(input)).toBe(input);
  });
});

describe("replaceUnencodable", () => {
  it("replaces code points the font cannot encode with ?", () => {
    const canEncode = (cp: number) => cp < 128;
    expect(replaceUnencodable("A→B", canEncode)).toBe("A?B");
  });
});
