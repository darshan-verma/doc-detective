import { createHash, randomBytes } from "crypto";
import { prisma } from "../prisma";
import { AppError } from "../errors";
import { appendLogEntry, hashCertificateRecord } from "../trust";

export function hashOwnerToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** Generate a one-time owner token (return to client; store only the hash). */
export function issueOwnerToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashOwnerToken(token) };
}

export async function assertOwnerToken(
  certId: string,
  ownerToken: string,
): Promise<void> {
  const cert = await prisma.certificate.findUnique({ where: { certId } });
  if (!cert || !cert.ownerTokenHash) {
    throw new AppError("BAD_REQUEST", "Invalid parent certificate or token", 403);
  }
  if (cert.ownerTokenHash !== hashOwnerToken(ownerToken)) {
    throw new AppError("BAD_REQUEST", "Invalid owner token", 403);
  }
}

export async function revokeCertificate(
  certId: string,
  ownerToken: string,
  reason: string,
): Promise<void> {
  await assertOwnerToken(certId, ownerToken);
  const cert = await prisma.certificate.findUniqueOrThrow({ where: { certId } });
  if (cert.revokedAt) {
    throw new AppError("BAD_REQUEST", "Certificate already revoked", 400);
  }
  const revokedAt = new Date();
  await prisma.$transaction(async (tx) => {
    await tx.certificate.update({
      where: { certId },
      data: { revokedAt, revokeReason: reason.slice(0, 500) },
    });
    await appendLogEntry(
      {
        certId,
        eventType: "CERTIFICATE_REVOKED",
        recordHash: hashCertificateRecord({
          certId: cert.certId,
          sha256: cert.sha256,
          sizeBytes: cert.sizeBytes,
          keyId: cert.keyId,
          signature: cert.signature,
          createdAt: cert.createdAt,
        }),
        createdAt: revokedAt,
      },
      tx,
    );
  });
}

/** Newest certificate in a lineage (follows supersededBy). */
export async function findNewestVersion(certId: string) {
  let current = await prisma.certificate.findUnique({ where: { certId } });
  if (!current) return null;
  const seen = new Set<string>();
  while (current.supersededBy && !seen.has(current.certId)) {
    seen.add(current.certId);
    const next = await prisma.certificate.findUnique({
      where: { certId: current.supersededBy },
    });
    if (!next) break;
    current = next;
  }
  return current;
}

/** Lineage list from root to newest. */
export async function listLineage(certId: string) {
  const start = await prisma.certificate.findUnique({ where: { certId } });
  if (!start) return [];

  // Walk to root
  let root = start;
  const seen = new Set<string>();
  while (root.parentCertId && !seen.has(root.certId)) {
    seen.add(root.certId);
    const parent = await prisma.certificate.findUnique({
      where: { certId: root.parentCertId },
    });
    if (!parent) break;
    root = parent;
  }

  const lineage = [root];
  let cur = root;
  seen.clear();
  while (cur.supersededBy && !seen.has(cur.certId)) {
    seen.add(cur.certId);
    const next = await prisma.certificate.findUnique({
      where: { certId: cur.supersededBy },
    });
    if (!next) break;
    lineage.push(next);
    cur = next;
  }
  return lineage.map((c) => ({
    certId: c.certId,
    version: c.version,
    createdAt: c.createdAt.toISOString(),
    revokedAt: c.revokedAt?.toISOString() ?? null,
    supersededBy: c.supersededBy,
  }));
}
