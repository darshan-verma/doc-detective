import path from "path";
import { pathToFileURL } from "url";
import jsQR from "jsqr";
import { decodeImage, isCertifiableImage } from "../image";
import { normalizeCertId } from "../trust/ids";
import { withTimeout, IDENTIFY_STEP_TIMEOUT_MS } from "./timeout";

/** Pull certId from a /v/<certId> or /certificate/<certId> URL, or bare ID. */
export function certIdFromQrPayload(data: string): string | null {
  const trimmed = data.trim();
  try {
    const url = new URL(trimmed);
    const parts = url.pathname.split("/").filter(Boolean);
    const vIdx = parts.findIndex((p) => p === "v" || p === "certificate");
    if (vIdx >= 0 && parts[vIdx + 1]) {
      return normalizeCertId(parts[vIdx + 1]!);
    }
  } catch {
    // not a URL
  }
  return normalizeCertId(trimmed);
}

function decodeQrFromRgba(
  data: Uint8ClampedArray,
  width: number,
  height: number,
): string | null {
  const code = jsQR(data, width, height, { inversionAttempts: "attemptBoth" });
  return code?.data ?? null;
}

/** Decode QR from an image file. */
export async function decodeQrFromImage(
  bytes: Buffer,
): Promise<string | null> {
  const pixels = await decodeImage(bytes);
  return decodeQrFromRgba(pixels.data, pixels.width, pixels.height);
}

/** Render last PDF page and attempt QR decode. */
export async function decodeQrFromPdf(bytes: Buffer): Promise<string | null> {
  const { createCanvas } = await import("@napi-rs/canvas");
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const { analysisConfig } = await import("../analysis/config");

  const workerPath = path.join(
    process.cwd(),
    "node_modules",
    "pdfjs-dist",
    "legacy",
    "build",
    "pdf.worker.mjs",
  );
  pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(workerPath).href;

  const loadingTask = pdfjs.getDocument({
    data: new Uint8Array(bytes),
    useSystemFonts: true,
    disableFontFace: true,
  });
  const pdf = await loadingTask.promise;
  if (pdf.numPages < 1) return null;

  const page = await pdf.getPage(pdf.numPages);
  const scale = analysisConfig.pdfRenderDpi / 72;
  const viewport = page.getViewport({ scale });
  const canvas = createCanvas(
    Math.ceil(viewport.width),
    Math.ceil(viewport.height),
  );
  const ctx = canvas.getContext("2d");
  await page.render({
    canvasContext: ctx as unknown as CanvasRenderingContext2D,
    viewport,
  }).promise;
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return decodeQrFromRgba(
    new Uint8ClampedArray(imageData.data),
    canvas.width,
    canvas.height,
  );
}

export async function tryDecodeQrCertId(
  bytes: Buffer,
  filename: string,
  mimeType: string,
): Promise<{ certId: string | null; warning?: string }> {
  const timed = await withTimeout(
    (async () => {
      if (isCertifiableImage(mimeType, filename)) {
        const payload = await decodeQrFromImage(bytes);
        return payload ? certIdFromQrPayload(payload) : null;
      }
      const lower = filename.toLowerCase();
      if (mimeType === "application/pdf" || lower.endsWith(".pdf")) {
        const payload = await decodeQrFromPdf(bytes);
        return payload ? certIdFromQrPayload(payload) : null;
      }
      return null;
    })(),
    IDENTIFY_STEP_TIMEOUT_MS,
    "qr-decode",
  );

  if (!timed.ok) {
    return { certId: null, warning: timed.reason };
  }
  return { certId: timed.value };
}
