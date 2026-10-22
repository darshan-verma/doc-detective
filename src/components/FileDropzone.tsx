"use client";

import { useCallback, useRef, useState } from "react";

interface FileDropzoneProps {
  onFile: (file: File) => void;
  disabled?: boolean;
  accept?: string;
  /** When set, the dropzone shows this file instead of the empty prompt. */
  selectedFile?: File | null;
  onClear?: () => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function FileDropzone({
  onFile,
  disabled,
  accept,
  selectedFile,
  onClear,
}: FileDropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  const handleFiles = useCallback(
    (files: FileList | null) => {
      const file = files?.[0];
      if (file) onFile(file);
    },
    [onFile],
  );

  const openPicker = () => {
    if (!disabled) inputRef.current?.click();
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") openPicker();
      }}
      onClick={openPicker}
      onDragEnter={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        e.preventDefault();
        setDragging(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (!disabled) handleFiles(e.dataTransfer.files);
      }}
      className={`cursor-pointer rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
        dragging
          ? "border-sky-500 bg-sky-50"
          : selectedFile
            ? "border-sky-400 bg-sky-50/70 hover:border-sky-500"
            : "border-zinc-300 bg-zinc-50 hover:border-zinc-400"
      } ${disabled ? "pointer-events-none opacity-60" : ""}`}
    >
      {selectedFile ? (
        <div className="mx-auto flex max-w-md flex-col items-center gap-1">
          <p className="text-xs font-medium uppercase tracking-wide text-sky-700">
            File ready
          </p>
          <p className="truncate text-sm font-semibold text-zinc-900">
            {selectedFile.name}
          </p>
          <p className="text-xs text-zinc-500">
            {formatSize(selectedFile.size)}
            {selectedFile.type ? ` · ${selectedFile.type}` : ""}
          </p>
          <p className="mt-2 text-xs text-zinc-500">
            Click or drop another file to replace
          </p>
          {onClear && (
            <button
              type="button"
              className="mt-2 rounded-md border border-zinc-300 bg-white px-3 py-1 text-xs font-medium text-zinc-700 hover:bg-zinc-50"
              onClick={(e) => {
                e.stopPropagation();
                onClear();
              }}
            >
              Clear
            </button>
          )}
        </div>
      ) : (
        <>
          <p className="text-sm font-medium text-zinc-800">
            Drop a file here, or click to browse
          </p>
          <p className="mt-1 text-xs text-zinc-500">
            PDF, images, TXT, DOCX, or any other file
          </p>
        </>
      )}
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        accept={accept}
        disabled={disabled}
        onChange={(e) => {
          handleFiles(e.target.files);
          e.target.value = "";
        }}
      />
    </div>
  );
}
