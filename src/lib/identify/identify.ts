import type { Certificate } from "@prisma/client";
import { getConfig } from "../config";
import { parseCertIdFromFilename, sanitizeFilename } from "../filenames";
import { hashBuffer } from "../hashing";
import {
  decodeImage,
  extract,
  hamming,
  isCertifiableImage,
  phash64,
} from "../image";
import { prisma } from "../prisma";
import { publicCertificateView } from "../certificates/public-view";
import { watermarkTokenFromCertId } from "../trust/ids";
import { tryDecodeQrCertId } from "./qr";
import { simhashHamming, textSimhash64 } from "./simhash";
import { extractTextForSimhash, isDocumentForSimhash } from "./text";
import { IDENTIFY_STEP_TIMEOUT_MS, withTimeout } from "./timeout";
import type {
  IdentifyFingerprints,
  IdentifyResult,
  IdentifySignal,
  SimilarityCandidate,
} from "./types";

const PHASH_HAMMING_MAX = 12;
const SIMHASH_HAMMING_MAX = 3;

/** Lookup by 8-char watermark token (prefix of compact certId, or legacy ID). */
async function resolveWatermarkToken(
  token: string,
): Promise<Certificate | null> {
  const t = token.replace(/\0/g, "").trim().toUpperCase();
  if (!t) return null;
  const exact = await prisma.certificate.findUnique({ where: { certId: t } });
  if (exact) return exact;
  const matches = await prisma.certificate.findMany({
    where: { certId: { startsWith: t } },
    take: 2,
  });
  if (matches.length === 1) return matches[0]!;
  // Also match via watermarkTokenFromCertId prefix equality
  const allWithWm = await prisma.certificate.findMany({
    where: { watermarkVersion: { not: null } },
    select: { certId: true },
  });
  const hits = allWithWm.filter(
    (c) => watermarkTokenFromCertId(c.certId) === t.slice(0, 8),
  );
  if (hits.length === 1) {
    return prisma.certificate.findUnique({ where: { certId: hits[0]!.certId } });
  }
  return null;
}

interface AccSignal {
  certId: string;
  signals: IdentifySignal[];
}

function scoreSignals(signals: IdentifySignal[]): {
  score: number;
  filenameOnly: boolean;
} {
  if (signals.length === 0) return { score: 0, filenameOnly: false };
  let score = 0;
  let hasStrong = false;
  for (const s of signals) {
    switch (s.type) {
      case "watermark":
        score = Math.max(score, 1.0);
        hasStrong = true;
        break;
      case "qr_code":
        score = Math.max(score, 1.0);
        hasStrong = true;
        break;
      case "image_phash": {
        const d = s.hamming ?? PHASH_HAMMING_MAX;
        const contrib = 0.55 + 0.35 * (1 - d / PHASH_HAMMING_MAX);
        score = Math.max(score, contrib);
        hasStrong = true;
        break;
      }
      case "text_simhash": {
        const d = s.hamming ?? SIMHASH_HAMMING_MAX;
        const contrib = 0.55 + 0.35 * (1 - d / SIMHASH_HAMMING_MAX);
        score = Math.max(score, contrib);
        hasStrong = true;
        break;
      }
      case "filename_suffix":
        score = Math.max(score, 0.2);
        break;
    }
  }
  const filenameOnly =
    !hasStrong && signals.every((s) => s.type === "filename_suffix");
  return { score, filenameOnly };
}

function guessMime(filename: string, provided: string | null): string {
  if (provided && provided !== "application/octet-stream") return provided;
  const ext = filename.includes(".")
    ? filename.slice(filename.lastIndexOf(".")).toLowerCase()
    : "";
  const map: Record<string, string> = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".docx":
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
  };
  return map[ext] ?? "application/octet-stream";
}

async function findExactByHash(
  uploadHash: string,
): Promise<{ cert: Certificate; matchedOn: "sha256" | "inputSha256" } | null> {
  const bySha = await prisma.certificate.findFirst({
    where: { sha256: uploadHash },
  });
  if (bySha) return { cert: bySha, matchedOn: "sha256" };

  const byInput = await prisma.certificate.findFirst({
    where: { inputSha256: uploadHash },
  });
  if (byInput) return { cert: byInput, matchedOn: "inputSha256" };

  return null;
}

function addSignal(
  map: Map<string, AccSignal>,
  certId: string,
  signal: IdentifySignal,
): void {
  let entry = map.get(certId);
  if (!entry) {
    entry = { certId, signals: [] };
    map.set(certId, entry);
  }
  if (!entry.signals.some((s) => s.type === signal.type)) {
    entry.signals.push(signal);
  }
}

/**
 * Identify whether an upload matches an existing certificate.
 * Never throws: analysis failures yield NEW + warnings.
 */
export async function identifyFile(
  upload: File | { bytes: Buffer; name: string; type?: string },
): Promise<IdentifyResult> {
  const warnings: string[] = [];

  try {
    const originalName =
      upload instanceof File
        ? sanitizeFilename(upload.name || "file")
        : sanitizeFilename(upload.name || "file");
    const bytes =
      upload instanceof File
        ? Buffer.from(await upload.arrayBuffer())
        : upload.bytes;
    const mimeType = guessMime(
      originalName,
      upload instanceof File ? upload.type || null : upload.type ?? null,
    );

    if (bytes.length === 0) {
      return { kind: "NEW", warnings: ["Empty file"] };
    }

    const { sha256: inputSha256 } = await hashBuffer(bytes);

    // 1. Exact match on stored hash or original-input hash
    const exact = await findExactByHash(inputSha256);
    if (exact) {
      const view = publicCertificateView(exact.cert);
      return {
        kind: "EXACT",
        certificate: view,
        matchedOn: exact.matchedOn,
        revokedAt: exact.cert.revokedAt?.toISOString() ?? null,
        revokeReason: exact.cert.revokeReason,
      };
    }

    const signalMap = new Map<string, AccSignal>();
    let textSimhash: string | null = null;
    let imagePhash: string | null = null;

    // 2a. Filename suffix hint (weak)
    const fromName = parseCertIdFromFilename(originalName);
    if (fromName) {
      const exists = await prisma.certificate.findUnique({
        where: { certId: fromName },
      });
      if (exists) {
        addSignal(signalMap, fromName, {
          type: "filename_suffix",
          label: "Filename contains this certificate ID",
          weak: true,
        });
      }
    }

    // 2b. QR code
    const qr = await tryDecodeQrCertId(bytes, originalName, mimeType);
    if (qr.warning) warnings.push(qr.warning);
    if (qr.certId) {
      const exists = await prisma.certificate.findUnique({
        where: { certId: qr.certId },
      });
      if (exists) {
        addSignal(signalMap, qr.certId, {
          type: "qr_code",
          label: "QR code points to this certificate",
        });
      }
    }

    // 2c–2d. Image watermark + phash
    if (isCertifiableImage(mimeType, originalName)) {
      const imgTimed = await withTimeout(
        (async () => {
          const config = getConfig();
          const pixels = await decodeImage(bytes);
          const extracted = extract(pixels, {
            key: config.watermarkKey,
            step: config.watermarkQimStep,
          });
          const ph = phash64(pixels);
          return { extracted, ph };
        })(),
        IDENTIFY_STEP_TIMEOUT_MS,
        "image-fingerprint",
      );

      if (!imgTimed.ok) {
        warnings.push(imgTimed.reason);
      } else {
        imagePhash = imgTimed.value.ph;
        const { extracted } = imgTimed.value;
        const config = getConfig();
        if (
          extracted.confidence >= config.watermarkConfidenceMin &&
          extracted.payload
        ) {
          const wmCert = await resolveWatermarkToken(extracted.payload);
          if (wmCert) {
            addSignal(signalMap, wmCert.certId, {
              type: "watermark",
              label: "Embedded watermark matches this certificate",
              confidence: extracted.confidence,
            });
          }
        }

        const phashCandidates = await prisma.certificate.findMany({
          where: { imagePhash: { not: null } },
          select: { certId: true, imagePhash: true },
        });
        for (const c of phashCandidates) {
          if (!c.imagePhash) continue;
          const d = hamming(imagePhash, c.imagePhash);
          if (d <= PHASH_HAMMING_MAX) {
            addSignal(signalMap, c.certId, {
              type: "image_phash",
              label: `Perceptual hash is very close (distance ${d})`,
              hamming: d,
            });
          }
        }
      }
    }

    // 2e. Text SimHash for documents
    if (isDocumentForSimhash(originalName, mimeType)) {
      const textTimed = await withTimeout(
        (async () => {
          const text = await extractTextForSimhash(bytes, originalName, mimeType);
          if (!text || !text.trim()) return null;
          return textSimhash64(text);
        })(),
        IDENTIFY_STEP_TIMEOUT_MS,
        "text-simhash",
      );

      if (!textTimed.ok) {
        warnings.push(textTimed.reason);
      } else if (textTimed.value) {
        textSimhash = textTimed.value;
        const docs = await prisma.certificate.findMany({
          where: { textSimhash: { not: null } },
          select: { certId: true, textSimhash: true },
        });
        for (const c of docs) {
          if (!c.textSimhash) continue;
          const d = simhashHamming(textSimhash, c.textSimhash);
          if (d <= SIMHASH_HAMMING_MAX) {
            addSignal(signalMap, c.certId, {
              type: "text_simhash",
              label: `Document text fingerprint is very close (distance ${d})`,
              hamming: d,
            });
          }
        }
      }
    }

    if (signalMap.size === 0) {
      const fingerprints: IdentifyFingerprints = {
        inputSha256,
        textSimhash,
        imagePhash,
      };
      return {
        kind: "NEW",
        warnings: warnings.length ? warnings : undefined,
        fingerprints,
      };
    }

    const candidates: SimilarityCandidate[] = [];
    for (const acc of signalMap.values()) {
      const cert = await prisma.certificate.findUnique({
        where: { certId: acc.certId },
      });
      if (!cert) continue;
      const { score, filenameOnly } = scoreSignals(acc.signals);
      candidates.push({
        certId: acc.certId,
        signals: acc.signals,
        score,
        filenameOnly,
        certificate: publicCertificateView(cert),
      });
    }

    candidates.sort((a, b) => b.score - a.score);

    return {
      kind: "LIKELY_MODIFIED_COPY",
      candidates,
      warnings: warnings.length ? warnings : undefined,
    };
  } catch (err) {
    console.error("[identifyFile]", err);
    return {
      kind: "NEW",
      warnings: [
        `Analysis failed: ${err instanceof Error ? err.message : String(err)}`,
      ],
    };
  }
}
