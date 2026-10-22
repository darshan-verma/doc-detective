import { describe, expect, it } from "vitest";
import { diffText, smartLineDiff } from "../src/lib/diff/text";
import type { LineChange } from "../src/lib/diff/types";

describe("text diff", () => {
  it("identical text with different whitespace yields zero changes", () => {
    const a = "Hello\u00A0world\nLine  two\n";
    const b = "Hello world\nLine two\n";
    const result = smartLineDiff(a, b);
    expect(result.changes).toHaveLength(0);
    expect(result.moved).toHaveLength(0);
    expect(result.formattingOnlyDifferencesIgnored).toBe(true);
    expect(result.counts).toEqual({
      added: 0,
      removed: 0,
      changed: 0,
      moved: 0,
    });
  });

  it("reordered blocks yield only moved", () => {
    const a = "alpha\nbeta\ngamma\n";
    const b = "beta\ngamma\nalpha\n";
    const result = smartLineDiff(a, b);
    expect(result.changes).toHaveLength(0);
    expect(result.moved.length).toBeGreaterThan(0);
    expect(result.moved.every((c) => c.kind === "moved")).toBe(true);
    expect(result.counts.moved).toBe(result.moved.length);
    expect(result.counts.added + result.counts.removed + result.counts.changed).toBe(
      0,
    );
  });

  it("a single-word edit yields exactly one changed line with word-level change", () => {
    const a = "the quick brown fox\n";
    const b = "the slow brown fox\n";
    const result = smartLineDiff(a, b);
    expect(result.changes).toHaveLength(1);
    const change = result.changes[0]!;
    expect(change.kind).toBe("changed");
    expect(change.wordChanges).toBeDefined();
    const wordEdits = change.wordChanges!.filter((w) => w.added || w.removed);
    // one removed ("quick") + one added ("slow")
    expect(wordEdits).toHaveLength(2);
    expect(wordEdits.some((w) => w.removed && w.value.includes("quick"))).toBe(
      true,
    );
    expect(wordEdits.some((w) => w.added && w.value.includes("slow"))).toBe(
      true,
    );
    expect(result.counts.changed).toBe(1);
    expect(result.counts.added).toBe(0);
    expect(result.counts.removed).toBe(0);
  });

  it("a line inserted shifts no other lines into changed", () => {
    const a = "one\ntwo\nthree\n";
    const b = "one\nINSERTED\ntwo\nthree\n";
    const result = smartLineDiff(a, b);
    expect(result.counts.changed).toBe(0);
    expect(result.counts.added).toBe(1);
    expect(result.counts.removed).toBe(0);
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]!.kind).toBe("added");
    expect(result.changes[0]!.content).toBe("INSERTED");
  });

  it("reports summary counts on DiffResult", () => {
    const result = diffText("a\nb\n", "a\nc\n", 4, 4);
    expect(result.counts).toBeDefined();
    expect(typeof result.formattingOnlyDifferencesIgnored).toBe("boolean");
  });

  it("returns empty changes for identical text", () => {
    const result = diffText("same\n", "same\n", 5, 5);
    expect(result.changes).toHaveLength(0);
    expect((result.moved ?? []).length).toBe(0);
  });

  it("pairs a full-line rewrite as changed", () => {
    const result = diffText("one\ntwo\n", "one\nthree\n", 8, 10);
    const changes = result.changes as LineChange[];
    expect(changes.some((c) => c.kind === "changed")).toBe(true);
  });
});
