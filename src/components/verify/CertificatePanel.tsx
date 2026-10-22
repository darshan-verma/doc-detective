"use client";

import { useState } from "react";
import Link from "next/link";

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={`Copy ${label}`}
      onClick={async () => {
        await navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="rounded border border-zinc-200 px-1.5 py-0.5 text-[10px] text-zinc-600 hover:bg-zinc-50"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function CertificatePanel({
  certId,
  createdAt,
  timestampStatus,
  signatureValid,
  registeredSha256,
  uploadedSha256,
}: {
  certId: string;
  createdAt: string;
  timestampStatus?: string;
  signatureValid?: boolean;
  registeredSha256: string;
  uploadedSha256: string;
}) {
  return (
    <div className="space-y-3 rounded-lg border border-zinc-200 bg-white p-4 text-sm">
      <h3 className="font-semibold text-zinc-900">Certificate</h3>
      <dl className="space-y-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <dt className="w-36 shrink-0 text-xs text-zinc-500">Certificate ID</dt>
          <dd className="flex min-w-0 flex-1 items-center gap-2">
            <Link
              href={`/certificate/${certId}`}
              className="truncate font-mono text-xs text-sky-700 hover:underline"
            >
              {certId}
            </Link>
            <CopyButton value={certId} label="certificate ID" />
          </dd>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <dt className="w-36 shrink-0 text-xs text-zinc-500">Issued</dt>
          <dd className="text-xs text-zinc-800">
            {new Date(createdAt).toLocaleString()}
          </dd>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <dt className="w-36 shrink-0 text-xs text-zinc-500">Timestamp</dt>
          <dd className="text-xs text-zinc-800">
            {timestampStatus ?? "n/a"}
          </dd>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <dt className="w-36 shrink-0 text-xs text-zinc-500">Signature</dt>
          <dd className="text-xs text-zinc-800">
            {signatureValid == null
              ? "n/a"
              : signatureValid
                ? "Valid"
                : "Invalid"}
          </dd>
        </div>
        <div className="flex flex-wrap items-start gap-2">
          <dt className="w-36 shrink-0 text-xs text-zinc-500">
            Registered SHA-256
          </dt>
          <dd className="flex min-w-0 flex-1 items-start gap-2">
            <span className="break-all font-mono text-[11px] text-zinc-700">
              {registeredSha256}
            </span>
            <CopyButton value={registeredSha256} label="registered hash" />
          </dd>
        </div>
        <div className="flex flex-wrap items-start gap-2">
          <dt className="w-36 shrink-0 text-xs text-zinc-500">
            Uploaded SHA-256
          </dt>
          <dd className="flex min-w-0 flex-1 items-start gap-2">
            <span className="break-all font-mono text-[11px] text-zinc-700">
              {uploadedSha256}
            </span>
            <CopyButton value={uploadedSha256} label="uploaded hash" />
          </dd>
        </div>
      </dl>
    </div>
  );
}
