import Link from "next/link";
import {
  assertRecordIntegrity,
  getCertificateById,
  publicCertificateView,
} from "@/lib/certificates/service";
import { listLineage } from "@/lib/certificates/ownership";
import { prisma } from "@/lib/prisma";
import { formatCertId, isValidCertIdFormat, normalizeCertId } from "@/lib/trust/ids";
import { CertificateQr } from "./CertificateExtras";

export const dynamic = "force-dynamic";

export default async function CertificatePage({
  params,
}: {
  params: Promise<{ certId: string }>;
}) {
  const { certId: raw } = await params;

  if (!isValidCertIdFormat(raw)) {
    return (
      <div className="rounded-md bg-zinc-100 px-4 py-3 text-sm text-zinc-700">
        Certificate was not found.
      </div>
    );
  }

  const certId = normalizeCertId(raw)!;
  const cert = await getCertificateById(certId);
  if (!cert) {
    return (
      <div className="space-y-3">
        <div className="rounded-md bg-zinc-100 px-4 py-3 text-sm text-zinc-700">
          Certificate was not found.
        </div>
        <Link href="/verify" className="text-sm text-sky-700 hover:underline">
          Verify a file
        </Link>
      </div>
    );
  }

  try {
    await assertRecordIntegrity(cert);
  } catch {
    return (
      <div className="rounded-md bg-rose-50 px-4 py-3 text-sm text-rose-800">
        Certificate record signature is invalid — the record may have been
        altered.
      </div>
    );
  }

  const view = publicCertificateView(cert);
  const lineage = await listLineage(certId);

  const similarEarlier = cert.similarToCertId
    ? await getCertificateById(cert.similarToCertId)
    : null;
  const similarLater = await prisma.certificate.findMany({
    where: { similarToCertId: certId },
    orderBy: { createdAt: "asc" },
    select: { certId: true, createdAt: true },
  });

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-wider text-zinc-500">
          Public certificate
        </p>
        <h1 className="mt-1 font-mono text-2xl font-semibold tracking-wide text-zinc-900">
          {view.certIdDisplay ?? formatCertId(view.certId)}
        </h1>
        <p className="mt-1 font-mono text-xs text-zinc-500">{view.certId}</p>
        {view.revokedAt && (
          <p className="mt-2 rounded-md bg-rose-50 px-3 py-2 text-sm text-rose-800">
            REVOKED{view.revokeReason ? `: ${view.revokeReason}` : ""}
          </p>
        )}
      </div>

      <CertificateQr certId={view.certId} />

      {similarEarlier && (
        <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950">
          Resembles earlier certificate{" "}
          <Link
            href={`/certificate/${similarEarlier.certId}`}
            className="font-mono font-medium text-sky-800 hover:underline"
          >
            {formatCertId(similarEarlier.certId)}
          </Link>{" "}
          (issued {similarEarlier.createdAt.toLocaleString()})
        </p>
      )}

      {similarLater.length > 0 && (
        <div className="rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-sm text-zinc-800">
          <p className="font-medium">A similar file was certified later:</p>
          <ul className="mt-1 space-y-1">
            {similarLater.map((s) => (
              <li key={s.certId}>
                <Link
                  href={`/certificate/${s.certId}`}
                  className="font-mono text-sky-700 hover:underline"
                >
                  {formatCertId(s.certId)}
                </Link>{" "}
                <span className="text-zinc-500">
                  ({s.createdAt.toLocaleString()})
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <dl className="space-y-4 rounded-lg border border-zinc-200 bg-white p-5 text-sm shadow-sm">
        {"originalName" in view && view.originalName && (
          <div>
            <dt className="text-zinc-500">Original name</dt>
            <dd className="font-medium">{view.originalName}</dd>
          </div>
        )}
        {"certifiedFileName" in view && view.certifiedFileName && (
          <div>
            <dt className="text-zinc-500">Certified filename</dt>
            <dd className="font-mono text-xs">{view.certifiedFileName}</dd>
          </div>
        )}
        {view.mimeType && (
          <div>
            <dt className="text-zinc-500">MIME type</dt>
            <dd>{view.mimeType}</dd>
          </div>
        )}
        {view.sizeBytes != null && (
          <div>
            <dt className="text-zinc-500">Size</dt>
            <dd>{view.sizeBytes.toLocaleString()} bytes</dd>
          </div>
        )}
        <div>
          <dt className="text-zinc-500">SHA-256</dt>
          <dd className="break-all font-mono text-xs">{view.sha256}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Timestamp status</dt>
          <dd className="font-medium">{view.timestampStatus}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Key ID</dt>
          <dd className="font-mono text-xs">{view.keyId}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Protection</dt>
          <dd className="text-xs">
            {(view.protectionMethods ?? []).join(", ")}
          </dd>
        </div>
        <div>
          <dt className="text-zinc-500">Signature algorithm</dt>
          <dd className="font-mono text-xs">{view.signatureAlg}</dd>
        </div>
        <div>
          <dt className="text-zinc-500">Issued</dt>
          <dd>{new Date(view.createdAt).toLocaleString()}</dd>
        </div>
      </dl>

      {lineage.length > 1 && (
        <div className="space-y-2">
          <h2 className="text-sm font-medium text-zinc-900">Version history</h2>
          <ul className="space-y-1 text-sm">
            {lineage.map((v) => (
              <li key={v.certId} className="font-mono text-xs">
                v{v.version}{" "}
                <Link
                  href={`/certificate/${v.certId}`}
                  className="text-sky-700 hover:underline"
                >
                  {v.certId}
                </Link>{" "}
                — {new Date(v.createdAt).toLocaleString()}
                {v.revokedAt ? " · REVOKED" : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap gap-3 text-sm">
        <a
          href={`/api/download/${view.certId}`}
          className="rounded-md bg-zinc-900 px-4 py-2 font-medium text-white hover:bg-zinc-800"
        >
          Download certified file
        </a>
        <a
          href={`/api/certificate/${view.certId}/proof`}
          className="rounded-md border border-zinc-300 bg-white px-4 py-2 font-medium text-zinc-800 hover:bg-zinc-50"
        >
          Download proof bundle
        </a>
        <Link
          href={`/v/${view.certId}`}
          className="rounded-md border border-zinc-300 bg-white px-4 py-2 font-medium text-zinc-800 hover:bg-zinc-50"
        >
          Short verify link
        </Link>
        <Link
          href="/verify"
          className="rounded-md border border-zinc-300 bg-white px-4 py-2 font-medium text-zinc-800 hover:bg-zinc-50"
        >
          Verify a file
        </Link>
      </div>
    </div>
  );
}
