export type DiffType = "text" | "pdf" | "docx" | "binary" | "image";

export interface WordChange {
  value: string;
  added?: boolean;
  removed?: boolean;
}

export interface LineChange {
  kind: "added" | "removed" | "changed" | "moved";
  lineNumber?: number;
  originalLineNumber?: number;
  uploadedLineNumber?: number;
  /** Display content (uploaded / destination for moved+changed). */
  content: string;
  /** Prior content for changed / moved (original / source). */
  previousContent?: string;
  /** Word-level diff for kind === "changed". */
  wordChanges?: WordChange[];
}

export interface DiffCounts {
  added: number;
  removed: number;
  changed: number;
  moved: number;
}

export interface PageChange {
  page: number;
  /** Substantive changes (added / removed / changed) — moved excluded. */
  changes: LineChange[];
  /** Lines that only changed position (collapsed in UI). */
  moved?: LineChange[];
  summary?: string;
  counts?: DiffCounts;
  formattingOnlyDifferencesIgnored?: boolean;
}

export interface ByteRangeChange {
  start: number;
  end: number;
  chunkIndex: number;
}

export type DiffStatus = "OK" | "ANALYSIS_UNAVAILABLE";

export interface DiffResult {
  type: DiffType;
  summary: string;
  changes: LineChange[] | PageChange[] | ByteRangeChange[];
  /** Moved lines for non-page (text/docx) diffs — excluded from `changes`. */
  moved?: LineChange[];
  originalSize: number;
  uploadedSize: number;
  note?: string;
  /** Set when content analysis could not run (e.g. corrupt PDF). */
  status?: DiffStatus;
  /** Human-readable detail for status !== OK. */
  message?: string;
  pageCount?: { original: number; uploaded: number };
  counts?: DiffCounts;
  /** True when raw text differed but normalized text did not (for some lines). */
  formattingOnlyDifferencesIgnored?: boolean;
  imageMeta?: {
    original?: { width?: number; height?: number };
    uploaded?: { width?: number; height?: number };
  };
}
