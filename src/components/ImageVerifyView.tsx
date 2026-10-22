"use client";

import { useEffect, useMemo, useRef, useState } from "react";

export interface ImageAnalysisView {
  watermark: { found: boolean; confidence: number };
  visualDistance: number;
  tamperScore: number;
  changedPercent: number;
  changedRegions: number;
  changedCells: Array<{ x: number; y: number }>;
  gridSize: number;
  width: number;
  height: number;
  matchedBy?: string;
  reason?: string;
}

export interface CertificatePanelData {
  certId: string;
  originalName?: string;
  sha256: string;
  createdAt: string;
  protectionMethods?: string[];
  signatureAlg?: string;
}

interface Props {
  file: File;
  analysis: ImageAnalysisView;
  certificate?: CertificatePanelData | null;
  signatureValid?: boolean;
  uploadedSha256: string;
  result: string;
}

export function ImageVerifyView({
  file,
  analysis,
  certificate,
  signatureValid,
  uploadedSha256,
  result,
}: Props) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const imgRef = useRef<HTMLImageElement>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const url = URL.createObjectURL(file);
    setObjectUrl(url);
    setReady(false);
    return () => URL.revokeObjectURL(url);
  }, [file]);

  const changedSet = useMemo(() => {
    const s = new Set<string>();
    for (const c of analysis.changedCells) {
      s.add(`${c.x},${c.y}`);
    }
    return s;
  }, [analysis.changedCells]);

  const grid = analysis.gridSize || 32;

  return (
    <div className="space-y-4">
      <div className="overflow-auto rounded-lg border border-zinc-200 bg-zinc-50 p-2">
        {objectUrl && (
          <div className="relative mx-auto inline-block max-w-full">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              ref={imgRef}
              src={objectUrl}
              alt="Uploaded image (original is never served)"
              className="block max-h-[480px] max-w-full"
              onLoad={() => setReady(true)}
            />
            {ready && analysis.reason !== "dimensions differ" && (
              <div
                className="pointer-events-none absolute inset-0"
                aria-hidden
                style={{
                  display: "grid",
                  gridTemplateColumns: `repeat(${grid}, 1fr)`,
                  gridTemplateRows: `repeat(${grid}, 1fr)`,
                }}
              >
                {Array.from({ length: grid * grid }, (_, i) => {
                  const x = i % grid;
                  const y = Math.floor(i / grid);
                  const changed = changedSet.has(`${x},${y}`);
                  return (
                    <div
                      key={i}
                      className={
                        changed
                          ? "bg-rose-500/45 outline outline-1 outline-rose-600/40"
                          : "outline outline-[0.5px] outline-white/10"
                      }
                    />
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
      <p className="text-xs text-zinc-500">
        Uploaded image with {grid}×{grid} cell overlay
        {analysis.changedCells.length > 0
          ? ` — ${analysis.changedCells.length} changed cell(s) tinted red`
          : ""}. The certified original is never served.
      </p>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-zinc-900">E-Certificate</h3>
          {certificate ? (
            <dl className="mt-3 space-y-2 text-sm">
              <div>
                <dt className="text-zinc-500">Certificate ID</dt>
                <dd className="font-mono font-semibold tracking-wide">
                  {certificate.certId}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">Issued</dt>
                <dd>{new Date(certificate.createdAt).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-zinc-500">Original filename</dt>
                <dd className="break-all">{certificate.originalName ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-zinc-500">Protection methods</dt>
                <dd className="text-xs">
                  {(certificate.protectionMethods ?? ["sha256", "ed25519"]).join(
                    ", ",
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">Signature status</dt>
                <dd
                  className={
                    signatureValid
                      ? "text-emerald-700"
                      : "font-medium text-rose-700"
                  }
                >
                  {signatureValid === undefined
                    ? "—"
                    : signatureValid
                      ? "Valid (Ed25519)"
                      : "INVALID"}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">Registered SHA-256</dt>
                <dd className="break-all font-mono text-xs">
                  {certificate.sha256}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="mt-2 text-sm text-zinc-500">No certificate matched.</p>
          )}
        </section>

        <section className="rounded-lg border border-zinc-200 bg-white p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-zinc-900">
            Technical analysis
          </h3>
          <dl className="mt-3 space-y-2 text-sm">
            <div>
              <dt className="text-zinc-500">Result</dt>
              <dd className="font-medium">{result}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Matched by</dt>
              <dd className="font-mono text-xs">
                {analysis.matchedBy ?? "—"}
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Watermark confidence</dt>
              <dd>
                {analysis.watermark.found ? "found" : "not found"} ·{" "}
                {(analysis.watermark.confidence * 100).toFixed(1)}%
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Visual distance</dt>
              <dd>{analysis.visualDistance.toFixed(2)} (avg cell Hamming)</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Tamper score</dt>
              <dd>{analysis.tamperScore.toFixed(3)}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Changed area</dt>
              <dd>
                {analysis.changedPercent.toFixed(2)}%
                {analysis.reason ? ` · ${analysis.reason}` : ""}
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Uploaded SHA-256</dt>
              <dd className="break-all font-mono text-xs">{uploadedSha256}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Upload size</dt>
              <dd>
                {analysis.width}×{analysis.height}
              </dd>
            </div>
          </dl>
        </section>
      </div>
    </div>
  );
}
