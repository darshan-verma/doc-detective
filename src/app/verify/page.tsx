"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { DiffView } from "@/components/DiffView";
import { FileDropzone } from "@/components/FileDropzone";
import { ImageVerifyView } from "@/components/ImageVerifyView";
import { CertificatePanel } from "@/components/verify/CertificatePanel";
import { ChecksPanel } from "@/components/verify/ChecksPanel";
import { PageChangeCards } from "@/components/verify/PageChangeCards";
import type { DiffResult } from "@/lib/diff";
import { consumeVerifyHandoff } from "@/lib/verify-handoff";

interface ImageAnalysis {
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

interface Explanation {
  headline: string;
  explanation: string;
  confidenceBadge: { label: string; reason: string };
  whatWeChecked: Array<{
    name: string;
    label: string;
    status: string;
    detail?: string;
  }>;
  whatWeCouldNotCheck: string[];
  formatDifferences?: Array<{ description: string }>;
  disclaimer: string;
}

interface VerifyResponse {
  result: string;
  uploadedSha256: string;
  certId?: string;
  message: string;
  signatureValid?: boolean;
  diff?: DiffResult;
  imageAnalysis?: ImageAnalysis;
  explanation?: Explanation;
  analysis?: {
    verdict: string;
    confidence: string;
    checks: Array<{ name: string; status: string; detail?: string }>;
    changes: Array<{ description: string; kind?: string; location?: string }>;
    notChecked: string[];
    formatDifferences?: Array<{ description: string }>;
    visualPages?: Array<{
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
    }>;
  };
  newerVersion?: { certId: string; version: number } | null;
  certificate?: {
    certId: string;
    originalName?: string;
    sha256: string;
    createdAt: string;
    protectionMethods?: string[];
    signatureAlg?: string;
    timestampStatus?: string;
  };
}

function bannerClasses(result: string) {
  switch (result) {
    case "AUTHENTIC":
      return "border-emerald-200 bg-emerald-50 text-emerald-900";
    case "MODIFIED_FORMAT_ONLY":
    case "MODIFIED_REENCODED":
      return "border-amber-200 bg-amber-50 text-amber-950";
    case "TAMPERED":
    case "REVOKED":
      return "border-rose-200 bg-rose-50 text-rose-900";
    default:
      return "border-zinc-300 bg-zinc-100 text-zinc-800";
  }
}

function VerdictIcon({ result }: { result: string }) {
  if (result === "AUTHENTIC") return <span aria-hidden>◎</span>;
  if (result === "MODIFIED_FORMAT_ONLY" || result === "MODIFIED_REENCODED")
    return <span aria-hidden>△</span>;
  if (result === "TAMPERED" || result === "REVOKED")
    return <span aria-hidden>✕</span>;
  return <span aria-hidden>○</span>;
}

function VerifyInner() {
  const searchParams = useSearchParams();
  const [certId, setCertId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyResponse | null>(null);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [reportHash, setReportHash] = useState<string | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const autoRan = useRef(false);

  useEffect(() => {
    const fromQuery = searchParams.get("certId");
    if (fromQuery) setCertId(fromQuery);
  }, [searchParams]);

  const runVerify = useCallback(async (file: File, certIdOverride?: string) => {
    setBusy(true);
    setError(null);
    setResult(null);
    setReportHash(null);
    setReportError(null);
    setUploadedFile(file);

    const resolvedCertId = (certIdOverride ?? certId).trim();
    if (resolvedCertId) setCertId(resolvedCertId);

    try {
      const form = new FormData();
      form.append("file", file);
      if (resolvedCertId) form.append("certId", resolvedCertId);

      const res = await fetch("/api/verify", { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error?.message || "Verification failed");
      }
      setResult(data as VerifyResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setBusy(false);
    }
  }, [certId]);

  async function handleFile(file: File) {
    await runVerify(file);
  }

  // Auto-run when arriving from certify "Verify against that certificate"
  useEffect(() => {
    if (autoRan.current) return;
    if (searchParams.get("autorun") !== "1") return;
    autoRan.current = true;
    const handoff = consumeVerifyHandoff();
    if (!handoff) return;
    void runVerify(handoff.file, handoff.certId);
  }, [searchParams, runVerify]);

  function resetForAnother() {
    setResult(null);
    setUploadedFile(null);
    setReportHash(null);
    setReportError(null);
    setError(null);
  }

  async function downloadReport() {
    if (!result?.certId || !result.certificate) return;
    setReportBusy(true);
    setReportError(null);
    try {
      const res = await fetch("/api/verify/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          certId: result.certId,
          verdict: result.result,
          uploadedSha256: result.uploadedSha256,
          registeredSha256: result.certificate.sha256,
          analysis: result.analysis,
          signatureValid: result.signatureValid,
          timestampStatus: result.certificate.timestampStatus,
          revoked: result.result === "REVOKED",
        }),
      });
      if (!res.ok) {
        let message = "Could not generate report";
        try {
          const data = await res.json();
          if (data?.error?.message) message = data.error.message;
        } catch {
          /* ignore */
        }
        setReportError(message);
        return;
      }
      const hash = res.headers.get("X-Report-SHA256");
      setReportHash(hash);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `doc-detective-report-${result.certId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setReportError(
        err instanceof Error ? err.message : "Could not generate report",
      );
    } finally {
      setReportBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-900">Verify a file</h1>
        <p className="mt-1 text-sm text-zinc-600">
          Upload any file. Images use watermark + perceptual matching; other
          files use content hash and format-aware analysis.
        </p>
      </div>

      {!result && (
        <>
          <label className="block text-sm">
            <span className="text-zinc-600">Certificate ID (optional)</span>
            <input
              type="text"
              value={certId}
              onChange={(e) => setCertId(e.target.value)}
              placeholder="DD-… or legacy ID"
              className="mt-1 w-full rounded-md border border-zinc-300 px-3 py-2 font-mono text-sm tracking-wider outline-none focus:border-sky-500 focus:ring-1 focus:ring-sky-500"
            />
          </label>
          <FileDropzone onFile={handleFile} disabled={busy} />
        </>
      )}

      {result && uploadedFile && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-dashed border-zinc-300 bg-zinc-50 px-4 py-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-zinc-900">
              {uploadedFile.name}
            </p>
            <p className="text-xs text-zinc-500">
              {(uploadedFile.size / 1024).toFixed(1)} KB
            </p>
          </div>
          <button
            type="button"
            onClick={resetForAnother}
            className="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm font-medium text-zinc-800 hover:bg-zinc-50"
          >
            Verify another file
          </button>
        </div>
      )}

      {busy && (
        <div className="rounded-md bg-sky-50 px-4 py-3 text-sm text-sky-800">
          Verifying…
        </div>
      )}

      {error && (
        <div className="rounded-md bg-rose-50 px-4 py-3 text-sm text-rose-800">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div
            className={`flex flex-wrap items-start justify-between gap-3 rounded-lg border px-4 py-4 ${bannerClasses(result.result)}`}
          >
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-lg">
                  <VerdictIcon result={result.result} />
                </span>
                <p className="text-lg font-semibold">
                  {result.explanation?.headline ??
                    result.result.replace(/_/g, " ")}
                </p>
              </div>
              <p className="text-sm opacity-90">
                {result.explanation?.explanation ?? result.message}
              </p>
              {result.explanation && (
                <span className="mt-2 inline-flex items-center rounded-full border border-current/20 bg-white/50 px-2.5 py-0.5 text-xs font-medium">
                  {result.explanation.confidenceBadge.label}:{" "}
                  {result.explanation.confidenceBadge.reason}
                </span>
              )}
            </div>
            {result.certId && (
              <div className="shrink-0 space-y-1">
                <button
                  type="button"
                  onClick={downloadReport}
                  disabled={reportBusy}
                  className="inline-flex items-center gap-2 rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-900 shadow-sm hover:bg-zinc-50 disabled:opacity-60"
                >
                  {reportBusy && (
                    <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-zinc-400 border-t-transparent" />
                  )}
                  Download report
                </button>
                {reportError && (
                  <p className="max-w-[220px] text-xs text-rose-700">
                    {reportError}
                  </p>
                )}
                {reportHash && (
                  <p className="max-w-[220px] break-all font-mono text-[10px] text-zinc-600">
                    Report SHA-256: {reportHash}
                  </p>
                )}
              </div>
            )}
          </div>

          {result.newerVersion && (
            <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
              A newer version exists:{" "}
              <Link
                href={`/certificate/${result.newerVersion.certId}`}
                className="font-mono underline"
              >
                {result.newerVersion.certId}
              </Link>{" "}
              (v{result.newerVersion.version})
            </div>
          )}

          {/* Certificate + changes first so the diff is visible with cert context */}
          {result.imageAnalysis && uploadedFile ? (
            <ImageVerifyView
              file={uploadedFile}
              analysis={result.imageAnalysis}
              certificate={result.certificate}
              signatureValid={result.signatureValid}
              uploadedSha256={result.uploadedSha256}
              result={result.result}
            />
          ) : (
            <div className="space-y-4">
              {result.certificate && result.certId && (
                <CertificatePanel
                  certId={result.certId}
                  createdAt={result.certificate.createdAt}
                  timestampStatus={result.certificate.timestampStatus}
                  signatureValid={result.signatureValid}
                  registeredSha256={result.certificate.sha256}
                  uploadedSha256={result.uploadedSha256}
                />
              )}
              {!result.certificate && (
                <dl className="space-y-2 text-sm">
                  <div>
                    <dt className="text-zinc-500">Uploaded SHA-256</dt>
                    <dd className="break-all font-mono text-xs">
                      {result.uploadedSha256}
                    </dd>
                  </div>
                </dl>
              )}
              {result.diff && <DiffView diff={result.diff} />}
            </div>
          )}

          {result.analysis?.visualPages &&
            result.analysis.visualPages.length > 0 && (
              <PageChangeCards pages={result.analysis.visualPages} />
            )}

          {result.explanation && (
            <ChecksPanel
              checks={[
                ...result.explanation.whatWeChecked,
                ...(result.signatureValid != null
                  ? [
                      {
                        name: "signature",
                        label: "Signature",
                        status: result.signatureValid ? "PASSED" : "FAILED",
                        detail: result.signatureValid
                          ? "Certificate record signature is valid"
                          : "Certificate record signature is invalid",
                      },
                    ]
                  : []),
              ]}
              couldNotCheck={result.explanation.whatWeCouldNotCheck}
              formatDifferences={
                result.explanation.formatDifferences ??
                result.analysis?.formatDifferences ??
                []
              }
              disclaimer={result.explanation.disclaimer}
            />
          )}
        </div>
      )}
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense fallback={<div className="text-sm text-zinc-500">Loading…</div>}>
      <VerifyInner />
    </Suspense>
  );
}
