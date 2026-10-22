import type { Certificate } from "@prisma/client";
import { certifiedFilename } from "../filenames";
import { formatCertId } from "../trust/ids";

/**
 * Public certificate metadata. LIMITED hides originalName / owner fields.
 * Always includes: certId, issued time, timestamp status, signature status,
 * sha256, and verdict-relevant protection methods.
 */
export function publicCertificateView(cert: Certificate) {
  const isImage = Boolean(cert.imagePhash);
  const isPublic = cert.visibility === "PUBLIC";
  return {
    certId: cert.certId,
    certIdDisplay: formatCertId(cert.certId),
    ...(isPublic
      ? {
          originalName: cert.originalName,
          certifiedFileName: certifiedFilename(cert.originalName, cert.certId, {
            forceExt: isImage ? ".png" : undefined,
          }),
        }
      : {}),
    mimeType: isPublic ? cert.mimeType : undefined,
    sizeBytes: isPublic ? cert.sizeBytes : undefined,
    sha256: cert.sha256,
    createdAt: cert.createdAt.toISOString(),
    signatureAlg: cert.signatureAlg,
    keyId: cert.keyId,
    timestampStatus: cert.timestampStatus,
    visibility: cert.visibility,
    width: isPublic ? cert.width : undefined,
    height: isPublic ? cert.height : undefined,
    imagePhash: isPublic ? cert.imagePhash : undefined,
    gridSize: isPublic ? cert.gridSize : undefined,
    watermarkVersion: isPublic ? cert.watermarkVersion : undefined,
    protectionMethods: isImage
      ? ["sha256", "ed25519", "dct-qim-watermark", "phash", "cell-signatures"]
      : ["sha256", "ed25519", "chunk-hashes"],
    version: cert.version,
    parentCertId: cert.parentCertId,
    similarToCertId: cert.similarToCertId ?? null,
    revokedAt: cert.revokedAt?.toISOString() ?? null,
    revokeReason: cert.revokeReason,
    supersededBy: cert.supersededBy,
  };
}
