"use client";

import { useState } from "react";

interface VerifyResult {
  ok: boolean;
  checkedFrom: number;
  checkedTo: number;
  brokenAt: number | null;
  reason?: string;
}

export function LogVerifyButton() {
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function verify() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/log/verify");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setResult((await res.json()) as VerifyResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verify failed");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-2">
      <button
        type="button"
        onClick={verify}
        disabled={loading}
        className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50"
      >
        {loading ? "Verifying…" : "Verify chain"}
      </button>
      {error && (
        <p className="text-sm text-rose-700">{error}</p>
      )}
      {result && (
        <div
          className={`rounded-md px-4 py-3 text-sm ${
            result.ok
              ? "bg-emerald-50 text-emerald-900"
              : "bg-rose-50 text-rose-900"
          }`}
        >
          {result.ok ? (
            <>
              Chain OK for seq {result.checkedFrom}–{result.checkedTo}
              {result.reason ? ` (${result.reason})` : ""}.
            </>
          ) : (
            <>
              Chain broken at seq {result.brokenAt}
              {result.reason ? `: ${result.reason}` : ""}.
            </>
          )}
        </div>
      )}
    </div>
  );
}
