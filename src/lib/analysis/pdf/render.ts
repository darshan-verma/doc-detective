import path from "path";
import { pathToFileURL } from "url";
import { analysisConfig } from "../config";

export interface RenderedPage {
  page: number;
  width: number;
  height: number;
  /** RGBA buffer */
  data: Buffer;
}

/** Render each PDF page to RGBA at ~pdfRenderDpi. */
export async function renderPdfPages(
  data: Buffer,
  maxPages = 50,
): Promise<RenderedPage[]> {
  // Native addon — must stay out of the Turbopack ESM graph (dynamic import).
  const { createCanvas } = await import("@napi-rs/canvas");
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
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
    data: new Uint8Array(data),
    useSystemFonts: true,
    disableFontFace: true,
  });
  const pdf = await loadingTask.promise;
  const pages: RenderedPage[] = [];
  const scale = analysisConfig.pdfRenderDpi / 72;
  const limit = Math.min(pdf.numPages, maxPages);

  for (let pageNum = 1; pageNum <= limit; pageNum++) {
    const page = await pdf.getPage(pageNum);
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
    pages.push({
      page: pageNum,
      width: canvas.width,
      height: canvas.height,
      data: Buffer.from(imageData.data),
    });
  }

  return pages;
}
