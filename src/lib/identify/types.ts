export interface PublicCertificateFields {
  certId: string;
  certIdDisplay: string;
  sha256: string;
  createdAt: string;
  signatureAlg: string;
  keyId: string;
  timestampStatus: string;
  visibility: string;
  protectionMethods: string[];
  version: number;
  parentCertId: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  similarToCertId?: string | null;
  originalName?: string;
  certifiedFileName?: string;
  mimeType?: string;
  sizeBytes?: number;
  width?: number | null;
  height?: number | null;
  imagePhash?: string | null;
  gridSize?: number;
  watermarkVersion?: number | null;
}

export type IdentifySignalType =
  | "filename_suffix"
  | "qr_code"
  | "watermark"
  | "image_phash"
  | "text_simhash";

export interface IdentifySignal {
  type: IdentifySignalType;
  /** Plain-language description for UI. */
  label: string;
  /** Weak evidence (e.g. filename suffix alone). */
  weak?: boolean;
  confidence?: number;
  hamming?: number;
}

export interface SimilarityCandidate {
  certId: string;
  signals: IdentifySignal[];
  score: number;
  /** True when the only signal is a filename suffix. */
  filenameOnly: boolean;
  certificate: PublicCertificateFields;
}

export type IdentifyResult =
  | {
      kind: "EXACT";
      certificate: PublicCertificateFields;
      matchedOn: "sha256" | "inputSha256";
      revokedAt: string | null;
      revokeReason: string | null;
    }
  | {
      kind: "LIKELY_MODIFIED_COPY";
      candidates: SimilarityCandidate[];
      warnings?: string[];
    }
  | {
      kind: "NEW";
      warnings?: string[];
      fingerprints?: IdentifyFingerprints;
    };

export interface IdentifyFingerprints {
  inputSha256: string;
  textSimhash: string | null;
  imagePhash: string | null;
}

/** Score threshold: candidates at or above this block certification unless force. */
export const STRONG_SCORE_THRESHOLD = 0.5;

export function isStrongCandidate(c: SimilarityCandidate): boolean {
  if (c.filenameOnly) return false;
  return c.score >= STRONG_SCORE_THRESHOLD;
}
