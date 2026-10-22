"use client";

import { useState } from "react";

export interface VisualPageCard {
  page: number;
  changedPercent: number;
  boxes: Array<{
    x: number;
    y: number;
    width: number;
    height: number;
    label?: string;
    normalized?: boolean;
  }>;
  uploadedThumbnailBase64?: string;
  originalThumbnailBase64?: string;
  thumbnailWidth?: number;
  thumbnailHeight?: number;
}

export function PageChangeCards({ pages }: { pages: VisualPageCard[] }) {
  const changed = pages.filter(
    (p) =>
      p.changedPercent > 0.15 ||
      p.boxes.length > 0 ||
      p.uploadedThumbnailBase64,
  );
  if (changed.length === 0) return null;

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-zinc-900">Where it changed</h3>
      <div className="grid gap-4 sm:grid-cols-2">
        {changed.map((p) => (
          <PageCard key={p.page} page={p} />
        ))}
      </div>
    </div>
  );
}

function PageCard({ page }: { page: VisualPageCard }) {
  const [mode, setMode] = useState<"uploaded" | "original">("uploaded");
  const src =
    mode === "original" && page.originalThumbnailBase64
      ? page.originalThumbnailBase64
      : page.uploadedThumbnailBase64;
  const hasToggle =
    Boolean(page.originalThumbnailBase64) &&
    Boolean(page.uploadedThumbnailBase64);

  return (
    <div className="overflow-hidden rounded-lg border border-zinc-200 bg-white">
      <div className="flex items-center justify-between border-b border-zinc-100 px-3 py-2">
        <div>
          <p className="text-sm font-medium text-zinc-900">Page {page.page}</p>
          <p className="text-xs text-zinc-500">
            {page.changedPercent.toFixed(2)}% pixels changed
          </p>
        </div>
        {hasToggle && (
          <div className="flex rounded-md border border-zinc-200 text-xs">
            <button
              type="button"
              onClick={() => setMode("uploaded")}
              className={`px-2 py-1 ${mode === "uploaded" ? "bg-zinc-900 text-white" : "text-zinc-600"}`}
            >
              Uploaded
            </button>
            <button
              type="button"
              onClick={() => setMode("original")}
              className={`px-2 py-1 ${mode === "original" ? "bg-zinc-900 text-white" : "text-zinc-600"}`}
            >
              Original
            </button>
          </div>
        )}
      </div>
      <div className="relative bg-zinc-50 p-2">
        {src ? (
          <div className="relative mx-auto inline-block max-w-full">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`data:image/png;base64,${src}`}
              alt={`Page ${page.page} ${mode}`}
              className="block max-h-72 max-w-full"
            />
            {mode === "uploaded" &&
              page.boxes.map((box, i) => (
                <div
                  key={i}
                  className="pointer-events-none absolute border-2 border-rose-500 bg-rose-500/20"
                  style={{
                    left: `${(box.normalized ? box.x : box.x) * 100}%`,
                    top: `${(box.normalized ? box.y : box.y) * 100}%`,
                    width: `${(box.normalized ? box.width : box.width) * 100}%`,
                    height: `${(box.normalized ? box.height : box.height) * 100}%`,
                  }}
                >
                  {box.label && (
                    <span className="absolute -top-5 left-0 whitespace-nowrap rounded bg-rose-600 px-1 text-[10px] text-white">
                      {box.label}
                    </span>
                  )}
                </div>
              ))}
          </div>
        ) : (
          <p className="px-2 py-8 text-center text-xs text-zinc-500">
            No thumbnail available · {page.boxes.length} region(s) flagged
          </p>
        )}
      </div>
    </div>
  );
}
