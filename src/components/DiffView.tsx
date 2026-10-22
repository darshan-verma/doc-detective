"use client";

import { useState } from "react";
import type {
  ByteRangeChange,
  DiffResult,
  LineChange,
  PageChange,
  WordChange,
} from "@/lib/diff";
import { sanitizeForDisplay } from "@/lib/sanitize";

function isLineChanges(changes: DiffResult["changes"]): changes is LineChange[] {
  return (
    Array.isArray(changes) &&
    (changes.length === 0 || "kind" in (changes[0] as object))
  );
}

function isPageChanges(changes: DiffResult["changes"]): changes is PageChange[] {
  return (
    Array.isArray(changes) &&
    (changes.length === 0 || "page" in (changes[0] as object))
  );
}

function isByteRanges(
  changes: DiffResult["changes"],
): changes is ByteRangeChange[] {
  return (
    Array.isArray(changes) &&
    (changes.length === 0 || "chunkIndex" in (changes[0] as object))
  );
}

function WordHighlight({ words }: { words: WordChange[] }) {
  return (
    <span className="whitespace-pre-wrap">
      {words.map((w, i) => {
        const value = sanitizeForDisplay(w.value);
        if (w.added) {
          return (
            <mark
              key={i}
              className="rounded-sm bg-emerald-200 text-emerald-900"
            >
              {value}
            </mark>
          );
        }
        if (w.removed) {
          return (
            <mark
              key={i}
              className="rounded-sm bg-rose-200 text-rose-900 line-through"
            >
              {value}
            </mark>
          );
        }
        return <span key={i}>{value}</span>;
      })}
    </span>
  );
}

function MovedSection({ moved }: { moved: LineChange[] }) {
  const [open, setOpen] = useState(false);
  if (moved.length === 0) return null;

  return (
    <div className="mt-2 rounded border border-zinc-200 bg-zinc-50">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-3 py-2 text-left text-xs font-medium text-zinc-600 hover:bg-zinc-100"
      >
        <span>
          Moved lines ({moved.length}) — position changed, text unchanged
        </span>
        <span className="text-zinc-400">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <ul className="space-y-1 border-t border-zinc-200 px-3 py-2 text-xs text-zinc-600">
          {moved.map((c, i) => (
            <li key={i}>
              ↕ L{c.originalLineNumber} → L{c.uploadedLineNumber}:{" "}
              {sanitizeForDisplay(c.content || c.previousContent || "")}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function LineDiffList({ changes }: { changes: LineChange[] }) {
  if (changes.length === 0) {
    return <p className="text-sm text-zinc-500">No line-level changes.</p>;
  }
  return (
    <ul className="space-y-1 text-xs leading-relaxed">
      {changes.map((c, i) => {
        if (c.kind === "added") {
          return (
            <li
              key={i}
              className="rounded bg-emerald-50 px-2 py-1 text-emerald-800"
            >
              + L{c.uploadedLineNumber}: {sanitizeForDisplay(c.content)}
            </li>
          );
        }
        if (c.kind === "removed") {
          return (
            <li key={i} className="rounded bg-rose-50 px-2 py-1 text-rose-800">
              − L{c.originalLineNumber}: {sanitizeForDisplay(c.content)}
            </li>
          );
        }
        if (c.kind === "changed") {
          return (
            <li key={i} className="rounded bg-amber-50 px-2 py-1 text-amber-900">
              ~ L{c.originalLineNumber}→{c.uploadedLineNumber}:{" "}
              {c.wordChanges && c.wordChanges.length > 0 ? (
                <WordHighlight words={c.wordChanges} />
              ) : (
                <>
                  <span className="text-rose-700 line-through">
                    {sanitizeForDisplay(c.previousContent ?? "")}
                  </span>{" "}
                  →{" "}
                  <span className="text-emerald-700">
                    {sanitizeForDisplay(c.content)}
                  </span>
                </>
              )}
            </li>
          );
        }
        return null;
      })}
    </ul>
  );
}

function pageStatsLine(page: PageChange): string {
  const changes = page.changes ?? [];
  const moved = page.moved?.length ?? 0;
  let added = 0;
  let removed = 0;
  let changed = 0;
  for (const c of changes) {
    if (c.kind === "added") added++;
    else if (c.kind === "removed") removed++;
    else if (c.kind === "changed") changed++;
  }
  return `${added} added, ${removed} removed, ${changed} changed, ${moved} moved`;
}

export function DiffView({ diff }: { diff: DiffResult }) {
  return (
    <div className="mt-4 space-y-3 rounded-lg border border-zinc-200 bg-white p-4">
      <div>
        <p className="text-sm font-medium text-zinc-900">
          {sanitizeForDisplay(diff.summary)}
        </p>
        <p className="mt-1 text-xs text-zinc-500">
          Type: {diff.type} · Original {diff.originalSize} bytes · Uploaded{" "}
          {diff.uploadedSize} bytes
        </p>
        {diff.formattingOnlyDifferencesIgnored && (
          <p className="mt-1 text-xs text-amber-700">
            Formatting-only differences were ignored (whitespace / Unicode
            normalization).
          </p>
        )}
        {diff.pageCount && (
          <p className="text-xs text-zinc-500">
            Pages: {diff.pageCount.original} → {diff.pageCount.uploaded}
          </p>
        )}
        {diff.imageMeta && (
          <p className="text-xs text-zinc-500">
            Dimensions:{" "}
            {diff.imageMeta.original
              ? `${diff.imageMeta.original.width}×${diff.imageMeta.original.height}`
              : "?"}{" "}
            →{" "}
            {diff.imageMeta.uploaded
              ? `${diff.imageMeta.uploaded.width}×${diff.imageMeta.uploaded.height}`
              : "?"}
          </p>
        )}
        {diff.note && (
          <p className="mt-2 rounded bg-zinc-100 px-2 py-1 text-xs text-zinc-600">
            {sanitizeForDisplay(diff.note)}
          </p>
        )}
      </div>

      {diff.type === "pdf" && diff.status === "ANALYSIS_UNAVAILABLE" && (
        <p className="rounded-md bg-amber-50 px-3 py-2 text-sm text-amber-900">
          {diff.message ??
            diff.summary ??
            "Could not analyze content; bytes differ"}
        </p>
      )}

      {diff.type === "pdf" &&
        diff.status !== "ANALYSIS_UNAVAILABLE" &&
        isPageChanges(diff.changes) && (
          <div className="space-y-4">
            {diff.changes.length === 0 ? (
              <p className="text-sm text-zinc-500">
                No page-level text changes.
              </p>
            ) : (
              diff.changes.map((page) => (
                <div key={page.page}>
                  <h4 className="mb-1 text-sm font-semibold text-zinc-800">
                    Page {page.page}
                  </h4>
                  <p className="mb-2 text-xs text-zinc-500">
                    {pageStatsLine(page)}
                  </p>
                  <LineDiffList changes={page.changes} />
                  {page.moved && page.moved.length > 0 && (
                    <MovedSection moved={page.moved} />
                  )}
                </div>
              ))
            )}
          </div>
        )}

      {(diff.type === "text" || diff.type === "docx") &&
        isLineChanges(diff.changes) && (
          <div>
            {diff.counts && (
              <p className="mb-2 text-xs text-zinc-500">
                {diff.counts.added} added, {diff.counts.removed} removed,{" "}
                {diff.counts.changed} changed, {diff.counts.moved} moved
              </p>
            )}
            <LineDiffList changes={diff.changes} />
            {diff.moved && diff.moved.length > 0 && (
              <MovedSection moved={diff.moved} />
            )}
          </div>
        )}

      {(diff.type === "binary" || diff.type === "image") &&
        isByteRanges(diff.changes) && (
          <ul className="space-y-1 font-mono text-xs text-zinc-700">
            {diff.changes.length === 0 ? (
              <li>No chunk ranges reported.</li>
            ) : (
              diff.changes.map((r) => (
                <li key={r.chunkIndex}>
                  Chunk {r.chunkIndex}: bytes {r.start}–{r.end}
                </li>
              ))
            )}
          </ul>
        )}
    </div>
  );
}
