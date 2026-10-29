"use client";

import { useState } from "react";

export interface CheckRow {
  name: string;
  label: string;
  status: string;
  detail?: string;
}

const STATUS_STYLES: Record<string, string> = {
  PASSED: "text-emerald-700 bg-emerald-50",
  FAILED: "text-rose-700 bg-rose-50",
  NOT_CHECKED: "text-zinc-600 bg-zinc-100",
};

function StatusIcon({ status }: { status: string }) {
  if (status === "PASSED") {
    return (
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-100 text-emerald-700 text-xs">
        ✓
      </span>
    );
  }
  if (status === "FAILED") {
    return (
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-rose-100 text-rose-700 text-xs">
        ✕
      </span>
    );
  }
  return (
    <span className="flex h-6 w-6 items-center justify-center rounded-full bg-zinc-100 text-zinc-500 text-xs">
      —
    </span>
  );
}

function shortResult(status: string, detail?: string): string {
  if (status === "PASSED") return detail?.split(";")[0] ?? "Match";
  if (status === "FAILED") {
    const d = detail ?? "Differences found";
    return d.length > 80 ? `${d.slice(0, 77)}…` : d;
  }
  return detail ?? "Not checked";
}

export function ChecksPanel({
  checks,
  couldNotCheck,
  formatDifferences,
  disclaimer,
}: {
  checks: CheckRow[];
  couldNotCheck: string[];
  formatDifferences: Array<{ description: string }>;
  disclaimer: string;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div className="space-y-3 rounded-lg border border-zinc-200 bg-white p-4">
      <h3 className="text-sm font-semibold text-zinc-900">What we checked</h3>
      <ul className="divide-y divide-zinc-100">
        {checks.map((c) => (
          <li key={c.name} className="py-2.5">
            <button
              type="button"
              className="flex w-full items-start gap-3 text-left"
              onClick={() =>
                setExpanded((cur) => (cur === c.name ? null : c.name))
              }
            >
              <StatusIcon status={c.status} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-zinc-900">
                    {c.label}
                  </span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${STATUS_STYLES[c.status] ?? STATUS_STYLES.NOT_CHECKED}`}
                  >
                    {c.status.replace(/_/g, " ")}
                  </span>
                </div>
                <p className="mt-0.5 text-xs text-zinc-600">
                  {shortResult(c.status, c.detail)}
                </p>
                {expanded === c.name && c.detail && (
                  <p className="mt-2 whitespace-pre-wrap rounded bg-zinc-50 px-2 py-1.5 text-xs text-zinc-700">
                    {c.detail}
                  </p>
                )}
              </div>
              <span className="text-xs text-zinc-400">
                {expanded === c.name ? "−" : "+"}
              </span>
            </button>
          </li>
        ))}
      </ul>

      {formatDifferences.length > 0 && (
        <div className="rounded-md border border-amber-100 bg-amber-50/60 px-3 py-2">
          <p className="text-xs font-medium text-amber-900">
            File was also re-saved by a different program
          </p>
          <ul className="mt-1 space-y-0.5 text-xs text-amber-800">
            {formatDifferences.map((d, i) => (
              <li key={i}>• {d.description}</li>
            ))}
          </ul>
        </div>
      )}

      {couldNotCheck.length > 0 && (
        <div>
          <h4 className="text-xs font-medium text-zinc-700">
            What we could not check
          </h4>
          <ul className="mt-1 list-disc pl-5 text-xs text-zinc-600">
            {couldNotCheck.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}

      {disclaimer ? (
        <p className="text-xs text-zinc-500">{disclaimer}</p>
      ) : null}
    </div>
  );
}
