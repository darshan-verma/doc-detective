import sharp from "sharp";
import type { PixelBuffer } from "./pixels";
import { lumaAt } from "./pixels";

export interface LocalizedRegion {
  x: number;
  y: number;
  width: number;
  height: number;
  area: number;
  /** Mean normalised residual in the component (ranking aid). */
  score?: number;
}

export interface PixelDiffOptions {
  /** Min region area at 1024×1024 reference (scales with image area). */
  minRegionArea?: number;
  /** MAD multiplier for pixel threshold (default 6). */
  outlierK?: number;
  /**
   * Absolute floor on the *normalised* residual map (default 3.5).
   * After tile normalisation quiet areas ≈ raw absdiff; JPEG noise tiles
   * compress toward ~1 so a lower floor than the old raw-diff 12 is needed.
   */
  absFloor?: number;
  /**
   * Min mean normalised residual for a component to count (default 15).
   * Filters soft glyph-edge resize noise (score ~8–14) while keeping
   * +20 luma patches after JPEG (score ~18) and content erasures (~80).
   */
  minRegionScore?: number;
  /**
   * Reject components with bbox aspect max/min above this (default 8).
   * Kills long stripe-edge bands from resize on ruled documents.
   */
  maxRegionAspect?: number;
  /** Max long side before diff (default 2048) — keeps 4k images under ~1s. */
  maxLongSide?: number;
}

export interface PixelDiffResult {
  tampered: boolean;
  reason: string;
  /** Bounding boxes in original (pre-downscale) coordinates. */
  regions: LocalizedRegion[];
  workingWidth: number;
  workingHeight: number;
  threshold: number;
  /** Fraction of working pixels above threshold (diagnostic only). */
  maskFraction: number;
}

const REF_AREA = 1024 * 1024;
const TILE = 32;
const FIT_SAMPLES = 20000;

/** Separable 3×3 Gaussian (approx σ≈0.85): [1,2,1]/4. */
function blur3x3(gray: Float64Array, w: number, h: number): Float64Array {
  const tmp = new Float64Array(w * h);
  const out = new Float64Array(w * h);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const xm = Math.max(0, x - 1);
      const xp = Math.min(w - 1, x + 1);
      tmp[y * w + x] =
        (gray[y * w + xm]! + 2 * gray[y * w + x]! + gray[y * w + xp]!) / 4;
    }
  }
  for (let y = 0; y < h; y++) {
    const ym = Math.max(0, y - 1);
    const yp = Math.min(h - 1, y + 1);
    for (let x = 0; x < w; x++) {
      out[y * w + x] =
        (tmp[ym * w + x]! + 2 * tmp[y * w + x]! + tmp[yp * w + x]!) / 4;
    }
  }
  return out;
}

function toGray(pixels: PixelBuffer): Float64Array {
  const out = new Float64Array(pixels.width * pixels.height);
  for (let y = 0; y < pixels.height; y++) {
    for (let x = 0; x < pixels.width; x++) {
      out[y * pixels.width + x] = lumaAt(pixels, x, y);
    }
  }
  return out;
}

function leastSquares(
  xs: Float64Array,
  ys: Float64Array,
  n: number,
): { a: number; b: number } {
  if (n < 2) return { a: 1, b: 0 };
  let sumX = 0;
  let sumY = 0;
  let sumXX = 0;
  let sumXY = 0;
  for (let i = 0; i < n; i++) {
    const x = xs[i]!;
    const y = ys[i]!;
    sumX += x;
    sumY += y;
    sumXX += x * x;
    sumXY += x * y;
  }
  const denom = n * sumXX - sumX * sumX;
  if (Math.abs(denom) < 1e-9) {
    return { a: 1, b: sumY / n - sumX / n };
  }
  const a = (n * sumXY - sumX * sumY) / denom;
  const b = (sumY - a * sumX) / n;
  if (!Number.isFinite(a) || !Number.isFinite(b)) return { a: 1, b: 0 };
  // Guard pathological fits (near-zero gain inverts contrast).
  if (a < 0.25 || a > 4) return { a: 1, b: sumY / n - sumX / n };
  return { a, b };
}

/**
 * Fit grayU ≈ a·grayO + b on a subsample; reject the top 5% residuals and
 * refit so local edits do not bias the global photometric model.
 */
function fitPhotometric(
  grayO: Float64Array,
  grayU: Float64Array,
): { a: number; b: number } {
  const n = grayO.length;
  const stride = Math.max(1, Math.floor(n / FIT_SAMPLES));
  const m = Math.ceil(n / stride);
  const xs = new Float64Array(m);
  const ys = new Float64Array(m);
  let count = 0;
  for (let i = 0; i < n; i += stride) {
    xs[count] = grayO[i]!;
    ys[count] = grayU[i]!;
    count++;
  }

  let { a, b } = leastSquares(xs, ys, count);

  const residuals = new Float64Array(count);
  for (let i = 0; i < count; i++) {
    residuals[i] = Math.abs(ys[i]! - (a * xs[i]! + b));
  }
  const sorted = Float64Array.from(residuals);
  sorted.sort();
  const keepIdx = Math.max(0, Math.floor(count * 0.95) - 1);
  const keepThresh = sorted[keepIdx]!;

  const xs2 = new Float64Array(count);
  const ys2 = new Float64Array(count);
  let n2 = 0;
  for (let i = 0; i < count; i++) {
    if (residuals[i]! <= keepThresh) {
      xs2[n2] = xs[i]!;
      ys2[n2] = ys[i]!;
      n2++;
    }
  }
  if (n2 >= 2) {
    ({ a, b } = leastSquares(xs2, ys2, n2));
  }
  return { a, b };
}

/**
 * Resample-tolerant residual: min |grayU(p) − alignedO(q)| over the 3×3
 * neighbourhood of p (absorbs 1px resize shifts).
 */
function resampleMinDiff(
  alignedO: Float64Array,
  grayU: Float64Array,
  w: number,
  h: number,
): Float64Array {
  const out = new Float64Array(w * h);
  for (let y = 0; y < h; y++) {
    const y0 = Math.max(0, y - 1);
    const y1 = Math.min(h - 1, y + 1);
    for (let x = 0; x < w; x++) {
      const x0 = Math.max(0, x - 1);
      const x1 = Math.min(w - 1, x + 1);
      const u = grayU[y * w + x]!;
      let minD = Infinity;
      for (let ny = y0; ny <= y1; ny++) {
        for (let nx = x0; nx <= x1; nx++) {
          const d = Math.abs(u - alignedO[ny * w + nx]!);
          if (d < minD) minD = d;
        }
      }
      out[y * w + x] = minD;
    }
  }
  return out;
}

/** Per-tile median of diffs; returns tileMedian[ty * tilesX + tx]. */
function tileMedians(
  diffs: Float64Array,
  w: number,
  h: number,
  tile: number,
): { medians: Float64Array; tilesX: number; tilesY: number } {
  const tilesX = Math.ceil(w / tile);
  const tilesY = Math.ceil(h / tile);
  const medians = new Float64Array(tilesX * tilesY);

  for (let ty = 0; ty < tilesY; ty++) {
    for (let tx = 0; tx < tilesX; tx++) {
      const x0 = tx * tile;
      const y0 = ty * tile;
      const x1 = Math.min(w, x0 + tile);
      const y1 = Math.min(h, y0 + tile);
      const buf: number[] = [];
      for (let y = y0; y < y1; y++) {
        for (let x = x0; x < x1; x++) {
          buf.push(diffs[y * w + x]!);
        }
      }
      buf.sort((a, b) => a - b);
      medians[ty * tilesX + tx] = buf[Math.floor(buf.length / 2)] ?? 0;
    }
  }
  return { medians, tilesX, tilesY };
}

function medianMadSampled(
  values: Float64Array,
  sampleStride: number,
): { median: number; mad: number } {
  const samples: number[] = [];
  for (let i = 0; i < values.length; i += sampleStride) {
    samples.push(values[i]!);
  }
  if (samples.length === 0) return { median: 0, mad: 0 };
  samples.sort((a, b) => a - b);
  const median = samples[Math.floor((samples.length - 1) / 2)]!;
  const devs = samples.map((v) => Math.abs(v - median));
  devs.sort((a, b) => a - b);
  const mad = devs[Math.floor((devs.length - 1) / 2)]!;
  return { median, mad };
}

interface Component {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  area: number;
  sumNorm: number;
}

/** 8-neighbour connected components on a boolean mask; accumulates score. */
function connectedComponents8(
  mask: Uint8Array,
  norm: Float64Array,
  w: number,
  h: number,
): Component[] {
  const visited = new Uint8Array(w * h);
  const comps: Component[] = [];
  const dirs: Array<[number, number]> = [
    [1, 0],
    [-1, 0],
    [0, 1],
    [0, -1],
    [1, 1],
    [1, -1],
    [-1, 1],
    [-1, -1],
  ];

  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const start = y * w + x;
      if (!mask[start] || visited[start]) continue;

      const stack = [start];
      visited[start] = 1;
      let area = 0;
      let sumNorm = 0;
      let minX = x;
      let maxX = x;
      let minY = y;
      let maxY = y;

      while (stack.length > 0) {
        const idx = stack.pop()!;
        area++;
        sumNorm += norm[idx]!;
        const cx = idx % w;
        const cy = Math.floor(idx / w);
        if (cx < minX) minX = cx;
        if (cx > maxX) maxX = cx;
        if (cy < minY) minY = cy;
        if (cy > maxY) maxY = cy;
        for (const [dx, dy] of dirs) {
          const nx = cx + dx;
          const ny = cy + dy;
          if (nx < 0 || ny < 0 || nx >= w || ny >= h) continue;
          const ni = ny * w + nx;
          if (!mask[ni] || visited[ni]) continue;
          visited[ni] = 1;
          stack.push(ni);
        }
      }

      comps.push({ minX, minY, maxX, maxY, area, sumNorm });
    }
  }

  comps.sort((a, b) => {
    const sa = a.sumNorm;
    const sb = b.sumNorm;
    if (sb !== sa) return sb - sa;
    return b.area - a.area;
  });
  return comps;
}

async function downscaleIfNeeded(
  pixels: PixelBuffer,
  maxLongSide: number,
): Promise<{ pixels: PixelBuffer; scale: number }> {
  const long = Math.max(pixels.width, pixels.height);
  if (long <= maxLongSide) {
    return { pixels, scale: 1 };
  }
  const scale = maxLongSide / long;
  const tw = Math.max(1, Math.round(pixels.width * scale));
  const th = Math.max(1, Math.round(pixels.height * scale));
  const { data, info } = await sharp(Buffer.from(pixels.data), {
    raw: {
      width: pixels.width,
      height: pixels.height,
      channels: 4,
    },
  })
    .resize(tw, th, { fit: "fill" })
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  return {
    pixels: {
      data: new Uint8ClampedArray(data),
      width: info.width,
      height: info.height,
    },
    scale,
  };
}

/**
 * Pixel-level second stage: detect sub-cell localized edits that the cell
 * classifier misses. Photometric alignment + 3×3 resample tolerance + per-tile
 * noise normalisation remove global brightness/contrast/JPEG structure so a
 * high mask fraction is no longer treated as "global → skip".
 */
export async function detectLocalizedPixelTamper(
  original: PixelBuffer,
  upload: PixelBuffer,
  options: PixelDiffOptions = {},
): Promise<PixelDiffResult> {
  const outlierK = options.outlierK ?? 6;
  const absFloor = options.absFloor ?? 3.5;
  const minRegionScore = options.minRegionScore ?? 15;
  const maxRegionAspect = options.maxRegionAspect ?? 8;
  const maxLongSide = options.maxLongSide ?? 2048;
  const minAreaRef = options.minRegionArea ?? 80;

  if (
    original.width !== upload.width ||
    original.height !== upload.height
  ) {
    return {
      tampered: false,
      reason: "Pixel stage skipped: dimension mismatch",
      regions: [],
      workingWidth: upload.width,
      workingHeight: upload.height,
      threshold: 0,
      maskFraction: 0,
    };
  }

  const downO = await downscaleIfNeeded(original, maxLongSide);
  const downU = await downscaleIfNeeded(upload, maxLongSide);
  const workO = downO.pixels;
  let workU = downU.pixels;
  if (workO.width !== workU.width || workO.height !== workU.height) {
    const { data, info } = await sharp(Buffer.from(upload.data), {
      raw: {
        width: upload.width,
        height: upload.height,
        channels: 4,
      },
    })
      .resize(workO.width, workO.height, { fit: "fill" })
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    workU = {
      data: new Uint8ClampedArray(data),
      width: info.width,
      height: info.height,
    };
  }

  const w = workO.width;
  const h = workO.height;
  const scaleBack = original.width / w;
  const workArea = w * h;

  const grayO = blur3x3(toGray(workO), w, h);
  const grayU = blur3x3(toGray(workU), w, h);

  // (a) Photometric alignment: grayU ≈ a·grayO + b
  const { a, b } = fitPhotometric(grayO, grayU);
  const alignedO = new Float64Array(workArea);
  for (let i = 0; i < workArea; i++) {
    alignedO[i] = a * grayO[i]! + b;
  }

  // (b) Resample-tolerant residual
  const rawDiff = resampleMinDiff(alignedO, grayU, w, h);

  // (c) Local noise normalisation by 32×32 tile median (floor 1).
  // Cap each tile median by ~2× the global median so a local edit that fills
  // most of a tile cannot inflate its own noise floor (which hid 24px patches).
  const sampleStrideRaw = Math.max(1, Math.floor(workArea / 250_000));
  const { median: globalRawMed } = medianMadSampled(rawDiff, sampleStrideRaw);
  const tileMedCap = Math.max(1, globalRawMed * 2);
  const { medians, tilesX } = tileMedians(rawDiff, w, h, TILE);
  const tilesY = Math.ceil(h / TILE);
  const norm = new Float64Array(workArea);
  for (let y = 0; y < h; y++) {
    const ty = Math.min(Math.floor(y / TILE), tilesY - 1);
    for (let x = 0; x < w; x++) {
      const tx = Math.min(Math.floor(x / TILE), tilesX - 1);
      const tileMed = medians[ty * tilesX + tx]!;
      const denom = Math.max(1, Math.min(tileMed, tileMedCap));
      norm[y * w + x] = rawDiff[y * w + x]! / denom;
    }
  }

  const sampleStride = Math.max(1, Math.floor(workArea / 250_000));
  const { median, mad } = medianMadSampled(norm, sampleStride);
  const threshold = Math.max(median + outlierK * mad * 1.4826, absFloor);

  const mask = new Uint8Array(workArea);
  let maskCount = 0;
  for (let i = 0; i < workArea; i++) {
    if (norm[i]! >= threshold) {
      mask[i] = 1;
      maskCount++;
    }
  }
  // (d) maskFraction is diagnostic only — never an early exit.
  const maskFraction = maskCount / workArea;

  const minArea = Math.max(
    1,
    Math.round(minAreaRef * (workArea / REF_AREA)),
  );

  const comps = connectedComponents8(mask, norm, w, h)
    .map((c) => {
      const bw = c.maxX - c.minX + 1;
      const bh = c.maxY - c.minY + 1;
      const aspect = Math.max(bw, bh) / Math.max(1, Math.min(bw, bh));
      return {
        ...c,
        score: c.sumNorm / Math.max(1, c.area),
        aspect,
      };
    })
    .filter(
      (c) =>
        c.area >= minArea &&
        c.score >= minRegionScore &&
        c.aspect <= maxRegionAspect,
    );

  const regions: LocalizedRegion[] = comps.map((c) => ({
    x: Math.round(c.minX * scaleBack),
    y: Math.round(c.minY * scaleBack),
    width: Math.round((c.maxX - c.minX + 1) * scaleBack),
    height: Math.round((c.maxY - c.minY + 1) * scaleBack),
    area: Math.round(c.area * scaleBack * scaleBack),
    score: c.score,
  }));

  // High mask + only mid-strength components → structured resample/re-encode
  // (e.g. every glyph edge after 70% resize), not a localized content edit.
  // Strong single edits (score ≳35) or low maskFraction still count.
  const topScore = regions[0]?.score ?? 0;
  if (
    regions.length > 0 &&
    maskFraction > 0.08 &&
    topScore < 35
  ) {
    return {
      tampered: false,
      reason: `Widespread mid-strength residuals (mask=${(maskFraction * 100).toFixed(2)}%, topScore=${topScore.toFixed(2)}, n=${regions.length}) look like resample/reencode`,
      regions,
      workingWidth: w,
      workingHeight: h,
      threshold,
      maskFraction,
    };
  }

  if (regions.length > 0) {
    return {
      tampered: true,
      reason: `Pixel-level region(s) differ (largest area=${regions[0]!.area}px, score=${topScore.toFixed(2)}, mask=${(maskFraction * 100).toFixed(2)}%, threshold=${threshold.toFixed(2)}, a=${a.toFixed(3)}, b=${b.toFixed(1)})`,
      regions,
      workingWidth: w,
      workingHeight: h,
      threshold,
      maskFraction,
    };
  }

  return {
    tampered: false,
    reason: `No localized pixel regions above area ${minArea} (mask=${(maskFraction * 100).toFixed(2)}%, threshold=${threshold.toFixed(2)}, a=${a.toFixed(3)}, b=${b.toFixed(1)})`,
    regions: [],
    workingWidth: w,
    workingHeight: h,
    threshold,
    maskFraction,
  };
}
