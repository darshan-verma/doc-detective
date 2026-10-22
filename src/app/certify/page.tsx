"use client";

import { useCallback, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  IdentifyUpload,
  type IdentifyApiResult,
  type IdentifyCandidateView,
} from "@/components/IdentifyUpload";
import { storeVerifyHandoff } from "@/lib/verify-handoff";

interface CertifyCreated {
  status: "CREATED";
  certId: string;
  certIdDisplay?: string;
  sha256: string;
  certifiedFileName: string;
  downloadUrl: string;
  sizeBytes: number;
  keyId?: string;
  timestampStatus?: string;
  ownerToken?: string;
  version?: number;
  stamped?: boolean;
  similarToCertId?: string | null;
}

type Phase =
  | { type: "idle" }
  | { type: "identified"; file: File; result: IdentifyApiResult }
  | { type: "created"; result: CertifyCreated }
  | {
      type: "already";
      status: "ALREADY_CERTIFIED" | "ALREADY_CERTIFIED_REVOKED";
      certificate: NonNullable<
        Extract<IdentifyApiResult, { kind: "EXACT" }>["certificate"]
      >;
      matchedOn: string;
      revocationNotice?: string;
    };

const OWNER_SESSION_KEY = "doc-detective-owner-certs";

function rememberOwnerCert(certId: string) {
  try {
    const raw = sessionStorage.getItem(OWNER_SESSION_KEY);
    const list: string[] = raw ? JSON.parse(raw) : [];
    if (!list.includes(certId)) {
      list.push(certId);
      sessionStorage.setItem(OWNER_SESSION_KEY, JSON.stringify(list));
    }
  } catch {
    /* ignore */
  }
}

function isOwnerSession(certId: string): boolean {
  try {
    const raw = sessionStorage.getItem(OWNER_SESSION_KEY);
    const list: string[] = raw ? JSON.parse(raw) : [];
    return list.includes(certId);
  } catch {
    return false;
  }
}

export default function CertifyPage() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>({ type: "idle" });
  const [copied, setCopied] = useState(false);
  const [addStamp, setAddStamp] = useState(false);
  const [parentCertId, setParentCertId] = useState("");
  const [ownerToken, setOwnerToken] = useState("");
  const [confirmSeparate, setConfirmSeparate] = useState(false);
  const [verifyBusy, setVerifyBusy] = useState(false);

  const onIdentified = useCallback((file: File, result: IdentifyApiResult) => {
    setError(null);
    if (result.kind === "EXACT") {
      setPhase({
        type: "already",
        status: result.revoked
          ? "ALREADY_CERTIFIED_REVOKED"
          : "ALREADY_CERTIFIED",
        certificate: result.certificate,
        matchedOn: result.matchedOn,
        revocationNotice: result.revoked
          ? result.revokeReason
            ? `This certificate was revoked: ${result.revokeReason}`
            : "This certificate was revoked."
          : undefined,
      });
      return;
    }
    setPhase({ type: "identified", file, result });
  }, []);

  async function doCertify(
    file: File,
    opts: {
      force?: boolean;
      parentCertId?: string;
      ownerToken?: string;
    } = {},
  ) {
    setBusy(true);
    setError(null);
    setProgress(`Certifying ${file.name}…`);
    setConfirmSeparate(false);
    try {
      const form = new FormData();
      form.append("file", file);
      if (addStamp) form.append("addVerificationStamp", "true");
      if (opts.force) form.append("force", "true");
      const parent = (opts.parentCertId ?? parentCertId).trim();
      const token = (opts.ownerToken ?? ownerToken).trim();
      if (parent && token) {
        form.append("parentCertId", parent);
        form.append("ownerToken", token);
      }
      const res = await fetch("/api/certify", { method: "POST", body: form });
      const data = await res.json();
      if (!res.ok) {
        if (data?.error?.code === "SIMILAR_CERTIFICATE_EXISTS") {
          setPhase({
            type: "identified",
            file,
            result: {
              kind: "LIKELY_MODIFIED_COPY",
              candidates: data.error.candidates ?? [],
            },
          });
          throw new Error(data.error.message);
        }
        throw new Error(data?.error?.message || "Certification failed");
      }
      if (
        data.status === "ALREADY_CERTIFIED" ||
        data.status === "ALREADY_CERTIFIED_REVOKED"
      ) {
        setPhase({
          type: "already",
          status: data.status,
          certificate: data.certificate,
          matchedOn: data.matchedOn,
          revocationNotice: data.revocationNotice,
        });
        return;
      }
      rememberOwnerCert(data.certId);
      setPhase({ type: "created", result: data as CertifyCreated });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Certification failed");
    } finally {
      setProgress(null);
      setBusy(false);
    }
  }

  async function copyId(text: string) {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  const strongCandidates: IdentifyCandidateView[] =
    phase.type === "identified" &&
    phase.result.kind === "LIKELY_MODIFIED_COPY"
      ? phase.result.candidates.filter((c) => c.strong !== false && !c.filenameOnly)
      : [];

  const isNew =
    phase.type === "identified" &&
    (phase.result.kind === "NEW" ||
      (phase.result.kind === "LIKELY_MODIFIED_COPY" &&
        strongCandidates.length === 0));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-900">Certify a file</h1>
        <p className="mt-1 text-sm text-zinc-600">
          We check whether the file is already certified, then compute a
          SHA-256 fingerprint, sign the certificate, and append it to the
          transparency log.
        </p>
      </div>

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium text-zinc-800">
          Verification stamp
        </legend>
        <label className="flex items-start gap-2 text-sm text-zinc-700">
          <input
            type="checkbox"
            checked={addStamp}
            onChange={(e) => setAddStamp(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            Add a QR stamp (PDF last page / image corner) so anyone can open
            the verification link by scanning.
          </span>
        </label>
        <p className="text-xs leading-relaxed text-zinc-500">
          {addStamp ? (
            <>
              <span className="font-medium text-amber-800">Stamping on:</span>{" "}
              we embed the QR into a copy of your file first, then fingerprint
              and certify that stamped copy. The original bytes are not what
              gets certified — download the stamped file after certifying and
              share that one.
            </>
          ) : (
            <>
              <span className="font-medium text-zinc-700">Stamping off:</span>{" "}
              we fingerprint your file exactly as uploaded. Best when you need
              byte-for-byte preservation. Verification still works via the
              certificate page and QR shown there (not embedded in the file).
            </>
          )}
        </p>
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-zinc-800">
          New version of an existing certificate{" "}
          <span className="font-normal text-zinc-500">(optional)</span>
        </legend>
        <p className="text-xs leading-relaxed text-zinc-500">
          Leave both blank for a brand-new document. Fill them in only when
          you are publishing an updated file that should sit in the same
          lineage as a certificate you already own — e.g. v2 of a contract.
          The parent cert ID is that earlier certificate; the owner token is
          the secret shown once when it was created (proof you control it).
          Anyone can certify a file; only the owner token can attach a new
          version to an existing chain.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="text-zinc-600">Parent cert ID</span>
            <input
              value={parentCertId}
              onChange={(e) => setParentCertId(e.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-300 px-3 py-2 font-mono text-xs"
              placeholder="DD-… from the previous version"
              autoComplete="off"
            />
          </label>
          <label className="block text-sm">
            <span className="text-zinc-600">Owner token</span>
            <input
              value={ownerToken}
              onChange={(e) => setOwnerToken(e.target.value)}
              className="mt-1 w-full rounded-md border border-zinc-300 px-3 py-2 font-mono text-xs"
              placeholder="secret from when parent was certified"
              autoComplete="off"
            />
          </label>
        </div>
        <p className="text-xs text-zinc-500">
          Lost owner tokens cannot be recovered yet (accounts coming later).
        </p>
      </fieldset>

      <IdentifyUpload
        disabled={busy}
        selectedFile={phase.type === "identified" ? phase.file : null}
        onClear={() => {
          setPhase({ type: "idle" });
          setError(null);
          setConfirmSeparate(false);
        }}
        onIdentified={onIdentified}
        onError={(m) => setError(m)}
        onBusyChange={setBusy}
      />

      {progress && (
        <div className="rounded-md bg-sky-50 px-4 py-3 text-sm text-sky-800">
          {progress}
        </div>
      )}

      {error && (
        <div className="rounded-md bg-rose-50 px-4 py-3 text-sm text-rose-800">
          {error}
        </div>
      )}

      {phase.type === "already" && phase.status === "ALREADY_CERTIFIED" && (
        <div className="space-y-4 rounded-lg border border-emerald-200 bg-emerald-50/60 p-5 shadow-sm">
          <h2 className="text-lg font-medium text-emerald-950">
            This file is already certified
          </h2>
          <dl className="space-y-3 text-sm">
            <div>
              <dt className="text-zinc-500">Certificate ID</dt>
              <dd className="mt-1 flex flex-wrap items-center gap-2 font-mono text-base font-semibold">
                <Link
                  href={`/certificate/${phase.certificate.certId}`}
                  className="text-sky-700 hover:underline"
                >
                  {phase.certificate.certIdDisplay ?? phase.certificate.certId}
                </Link>
                <button
                  type="button"
                  onClick={() => copyId(phase.certificate.certId)}
                  className="rounded border border-zinc-300 bg-white px-2 py-1 text-xs hover:bg-zinc-50"
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Issued</dt>
              <dd>{new Date(phase.certificate.createdAt).toLocaleString()}</dd>
            </div>
            <div>
              <dt className="text-zinc-500">Timestamp / signature</dt>
              <dd>
                {phase.certificate.timestampStatus ?? "PENDING"} ·{" "}
                {phase.certificate.signatureAlg ?? "ed25519"}
              </dd>
            </div>
            <div className="text-xs text-zinc-500">
              Matched on {phase.matchedOn}
            </div>
          </dl>
          <div className="flex flex-wrap gap-3">
            <Link
              href={`/certificate/${phase.certificate.certId}`}
              className="rounded-md border border-zinc-300 bg-white px-4 py-2 text-sm font-medium text-zinc-800 hover:bg-zinc-50"
            >
              View certificate
            </Link>
            {isOwnerSession(phase.certificate.certId) && (
              <a
                href={`/api/download/${phase.certificate.certId}`}
                className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800"
              >
                Download certified copy
              </a>
            )}
          </div>
        </div>
      )}

      {phase.type === "already" &&
        phase.status === "ALREADY_CERTIFIED_REVOKED" && (
          <div className="space-y-3 rounded-lg border border-amber-300 bg-amber-50 p-5 shadow-sm">
            <h2 className="text-lg font-medium text-amber-950">
              This file matches a revoked certificate
            </h2>
            <p className="text-sm text-amber-900">
              {phase.revocationNotice ?? "This certificate was revoked."}
            </p>
            <p className="font-mono text-sm">
              <Link
                href={`/certificate/${phase.certificate.certId}`}
                className="text-sky-700 hover:underline"
              >
                {phase.certificate.certIdDisplay ?? phase.certificate.certId}
              </Link>
            </p>
          </div>
        )}

      {phase.type === "identified" &&
        phase.result.kind === "LIKELY_MODIFIED_COPY" &&
        strongCandidates.length > 0 && (
          <div className="space-y-4 rounded-lg border border-amber-300 bg-amber-50 p-5 shadow-sm">
            <h2 className="text-lg font-medium text-amber-950">
              This looks like a modified copy of certificate{" "}
              <span className="font-mono">
                {strongCandidates[0]!.certificate.certIdDisplay ??
                  strongCandidates[0]!.certId}
              </span>
            </h2>
            <ul className="list-inside list-disc text-sm text-amber-950">
              {strongCandidates[0]!.signals.map((s) => (
                <li key={s.type + s.label}>{s.label}</li>
              ))}
            </ul>
            <div className="flex flex-wrap gap-3">
              <button
                type="button"
                disabled={busy || verifyBusy}
                onClick={async () => {
                  const targetId = strongCandidates[0]!.certId;
                  setVerifyBusy(true);
                  setError(null);
                  try {
                    await storeVerifyHandoff(phase.file, targetId);
                    router.push(`/verify?certId=${encodeURIComponent(targetId)}&autorun=1`);
                  } catch (err) {
                    setError(
                      err instanceof Error
                        ? err.message
                        : "Could not open verify",
                    );
                    setVerifyBusy(false);
                  }
                }}
                className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50"
              >
                {verifyBusy ? "Opening verify…" : "Verify against that certificate"}
              </button>
              <button
                type="button"
                disabled={busy || !ownerToken.trim()}
                onClick={() => {
                  const id = strongCandidates[0]!.certId;
                  setParentCertId(id);
                  void doCertify(phase.file, {
                    parentCertId: id,
                    ownerToken: ownerToken.trim(),
                  });
                }}
                className="rounded-md border border-zinc-300 bg-white px-4 py-2 text-sm font-medium text-zinc-800 hover:bg-zinc-50 disabled:opacity-50"
              >
                Certify as new version
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setConfirmSeparate(true)}
                className="rounded-md border border-amber-400 bg-amber-100/80 px-4 py-2 text-sm font-medium text-amber-950 hover:bg-amber-100"
              >
                Certify as a separate document
              </button>
            </div>
            {confirmSeparate && (
              <div className="rounded-md border border-amber-400 bg-white p-4 text-sm text-zinc-800">
                <p>
                  This will create a new certificate and publicly record that it
                  resembles certificate{" "}
                  <span className="font-mono">
                    {strongCandidates[0]!.certId}
                  </span>
                  . Continue?
                </p>
                <div className="mt-3 flex gap-2">
                  <button
                    type="button"
                    className="rounded-md bg-zinc-900 px-3 py-1.5 text-white"
                    onClick={() => void doCertify(phase.file, { force: true })}
                  >
                    Confirm
                  </button>
                  <button
                    type="button"
                    className="rounded-md border px-3 py-1.5"
                    onClick={() => setConfirmSeparate(false)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            <p className="text-xs text-zinc-600">
              To certify as a new version, enter the owner token above first.
            </p>
          </div>
        )}

      {isNew && phase.type === "identified" && (
        <div className="space-y-4 rounded-lg border border-sky-200 bg-sky-50/70 p-5 shadow-sm">
          <div>
            <h2 className="text-lg font-medium text-sky-950">
              Ready to certify
            </h2>
            <p className="mt-1 text-sm text-sky-900/80">
              <span className="font-medium text-sky-950">{phase.file.name}</span>
              {" · "}
              {phase.file.size < 1024
                ? `${phase.file.size} B`
                : phase.file.size < 1024 * 1024
                  ? `${(phase.file.size / 1024).toFixed(1)} KB`
                  : `${(phase.file.size / (1024 * 1024)).toFixed(1)} MB`}
            </p>
            <p className="mt-2 text-xs text-zinc-600">
              No existing certificate matched this file — it will get a new
              certificate ID, fingerprint, and log entry.
            </p>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={() => void doCertify(phase.file)}
            className="rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50"
          >
            Certify this file
          </button>
        </div>
      )}

      {phase.type === "created" && (
        <div className="space-y-4 rounded-lg border border-zinc-200 bg-white p-5 shadow-sm">
          <h2 className="text-lg font-medium text-zinc-900">Certified</h2>
          <dl className="space-y-3 text-sm">
            <div>
              <dt className="text-zinc-500">Certificate ID</dt>
              <dd className="font-mono text-base font-semibold tracking-wide">
                <Link
                  href={`/certificate/${phase.result.certId}`}
                  className="text-sky-700 hover:underline"
                >
                  {phase.result.certIdDisplay ?? phase.result.certId}
                </Link>
              </dd>
            </div>
            {phase.result.ownerToken && (
              <div>
                <dt className="text-zinc-500">
                  Owner token (shown once — save it)
                </dt>
                <dd className="break-all rounded bg-amber-50 px-2 py-1 font-mono text-xs text-amber-950">
                  {phase.result.ownerToken}
                </dd>
              </div>
            )}
            <div>
              <dt className="text-zinc-500">SHA-256</dt>
              <dd className="mt-1 flex flex-wrap items-center gap-2">
                <code className="break-all rounded bg-zinc-100 px-2 py-1 text-xs">
                  {phase.result.sha256}
                </code>
                <button
                  type="button"
                  onClick={() => copyId(phase.result.sha256)}
                  className="rounded border border-zinc-300 px-2 py-1 text-xs hover:bg-zinc-50"
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              </dd>
            </div>
            <div>
              <dt className="text-zinc-500">Version</dt>
              <dd>{phase.result.version ?? 1}</dd>
            </div>
            {phase.result.similarToCertId && (
              <div className="text-xs text-amber-800">
                Linked as resembling{" "}
                <Link
                  href={`/certificate/${phase.result.similarToCertId}`}
                  className="underline"
                >
                  {phase.result.similarToCertId}
                </Link>
              </div>
            )}
            {phase.result.stamped && (
              <div className="text-xs text-amber-800">
                File was stamped before hashing. Short link:{" "}
                <Link href={`/v/${phase.result.certId}`} className="underline">
                  /v/{phase.result.certId}
                </Link>
              </div>
            )}
          </dl>
          <a
            href={phase.result.downloadUrl}
            className="inline-flex rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800"
          >
            Download Certified File
          </a>
        </div>
      )}
    </div>
  );
}
