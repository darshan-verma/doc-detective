import { diffArrays, diffWords } from "diff";
import { normalizeText } from "./normalize";
import type {
  DiffCounts,
  DiffResult,
  LineChange,
  WordChange,
} from "./types";

export { normalizeText } from "./normalize";

function splitLines(text: string): string[] {
  if (text === "") return [];
  const lines = text.split("\n");
  if (text.endsWith("\n")) lines.pop();
  return lines;
}

function wordLevelDiff(previous: string, next: string): WordChange[] {
  return diffWords(previous, next).map((part) => ({
    value: part.value,
    ...(part.added ? { added: true } : {}),
    ...(part.removed ? { removed: true } : {}),
  }));
}

function summarizeCounts(counts: DiffCounts): string {
  const { added, removed, changed, moved } = counts;
  if (added + removed + changed + moved === 0) {
    return "No textual differences detected";
  }
  return `${added} added, ${removed} removed, ${changed} changed, ${moved} moved line(s)`;
}

export interface SmartLineDiffResult {
  changes: LineChange[];
  moved: LineChange[];
  counts: DiffCounts;
  formattingOnlyDifferencesIgnored: boolean;
}

/**
 * Line diff that compares via normalizeText, detects moved lines,
 * and attaches word-level diffs for genuine changes.
 */
export function smartLineDiff(
  original: string,
  uploaded: string,
): SmartLineDiffResult {
  const origLines = splitLines(original);
  const upLines = splitLines(uploaded);

  const parts = diffArrays(origLines, upLines, {
    comparator: (a, b) => normalizeText(a) === normalizeText(b),
  });

  type Pending = {
    content: string;
    lineNumber: number;
    norm: string;
  };

  const pendingRemoved: Pending[] = [];
  const pendingAdded: Pending[] = [];
  let formattingOnlyDifferencesIgnored = false;
  let oi = 0;
  let ui = 0;

  for (const part of parts) {
    const values = part.value as string[];
    if (part.added) {
      for (let i = 0; i < values.length; i++) {
        const content = upLines[ui]!;
        pendingAdded.push({
          content,
          lineNumber: ui + 1,
          norm: normalizeText(content),
        });
        ui += 1;
      }
    } else if (part.removed) {
      for (let i = 0; i < values.length; i++) {
        const content = origLines[oi]!;
        pendingRemoved.push({
          content,
          lineNumber: oi + 1,
          norm: normalizeText(content),
        });
        oi += 1;
      }
    } else {
      for (let i = 0; i < values.length; i++) {
        if (origLines[oi] !== upLines[ui]) {
          formattingOnlyDifferencesIgnored = true;
        }
        oi += 1;
        ui += 1;
      }
    }
  }

  // Moved: removed line whose normalized text matches an added line
  const moved: LineChange[] = [];
  const remainingRemoved: Pending[] = [];
  const remainingAdded = [...pendingAdded];

  for (const rem of pendingRemoved) {
    const idx = remainingAdded.findIndex((a) => a.norm === rem.norm);
    if (idx >= 0) {
      const add = remainingAdded[idx]!;
      remainingAdded.splice(idx, 1);
      // Only "moved" if position actually changed; same-index would be odd but skip equals
      if (rem.lineNumber !== add.lineNumber || rem.content !== add.content) {
        moved.push({
          kind: "moved",
          originalLineNumber: rem.lineNumber,
          uploadedLineNumber: add.lineNumber,
          content: add.content,
          previousContent: rem.content,
        });
      }
      // If content raw differs but norm equal and same... still formatting; already handled
      // for equal hunks. For moved with formatting-only content difference:
      if (rem.content !== add.content) {
        formattingOnlyDifferencesIgnored = true;
      }
    } else {
      remainingRemoved.push(rem);
    }
  }

  // Drop any remaining pair whose normalized text is equal (should be rare after comparator)
  const stillRemoved: Pending[] = [];
  const stillAdded = [...remainingAdded];
  for (const rem of remainingRemoved) {
    const idx = stillAdded.findIndex((a) => a.norm === rem.norm);
    if (idx >= 0) {
      const add = stillAdded[idx]!;
      stillAdded.splice(idx, 1);
      if (rem.content !== add.content) {
        formattingOnlyDifferencesIgnored = true;
      }
      // dropped — formatting-only, not a substantive change
    } else {
      stillRemoved.push(rem);
    }
  }

  // Pair leftover removed+added in order as "changed" with word-level diffs
  const changes: LineChange[] = [];
  const pairCount = Math.min(stillRemoved.length, stillAdded.length);
  for (let i = 0; i < pairCount; i++) {
    const rem = stillRemoved[i]!;
    const add = stillAdded[i]!;
    if (rem.norm === add.norm) {
      if (rem.content !== add.content) {
        formattingOnlyDifferencesIgnored = true;
      }
      continue;
    }
    changes.push({
      kind: "changed",
      originalLineNumber: rem.lineNumber,
      uploadedLineNumber: add.lineNumber,
      content: add.content,
      previousContent: rem.content,
      wordChanges: wordLevelDiff(rem.content, add.content),
    });
  }
  for (let i = pairCount; i < stillRemoved.length; i++) {
    const rem = stillRemoved[i]!;
    changes.push({
      kind: "removed",
      originalLineNumber: rem.lineNumber,
      content: rem.content,
    });
  }
  for (let i = pairCount; i < stillAdded.length; i++) {
    const add = stillAdded[i]!;
    changes.push({
      kind: "added",
      uploadedLineNumber: add.lineNumber,
      content: add.content,
    });
  }

  const counts: DiffCounts = {
    added: changes.filter((c) => c.kind === "added").length,
    removed: changes.filter((c) => c.kind === "removed").length,
    changed: changes.filter((c) => c.kind === "changed").length,
    moved: moved.length,
  };

  return {
    changes,
    moved,
    counts,
    formattingOnlyDifferencesIgnored,
  };
}

export function diffText(
  original: string,
  uploaded: string,
  originalSize: number,
  uploadedSize: number,
  type: DiffResult["type"] = "text",
): DiffResult {
  const smart = smartLineDiff(original, uploaded);

  const result: DiffResult = {
    type,
    summary: summarizeCounts(smart.counts),
    changes: smart.changes,
    moved: smart.moved,
    originalSize,
    uploadedSize,
    counts: smart.counts,
    formattingOnlyDifferencesIgnored: smart.formattingOnlyDifferencesIgnored,
  };

  if (
    smart.changes.length === 0 &&
    smart.moved.length === 0 &&
    originalSize !== uploadedSize
  ) {
    result.note =
      "Text content appears identical after normalization but file bytes differ (e.g. encoding or metadata).";
  } else if (
    smart.formattingOnlyDifferencesIgnored &&
    smart.changes.length === 0 &&
    smart.moved.length === 0
  ) {
    result.note =
      "Only formatting/whitespace differences were found and ignored.";
  }

  return result;
}
