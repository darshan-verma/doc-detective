import sharp from "sharp";
import type { PixelBuffer } from "./pixels";
import { lumaAt } from "./pixels";

export interface LocalizedRegion {
  x: number;
  y: number;
  width: number;
  height: number;
  area: number;
}

export interface PixelDiffOptions {
  /** Min region area at 1024×1024 reference (scales with image area). */
  minRegionArea?: number;
  /** MAD multiplier for pixel threshold (default 6). */
  outlierK?: number;
  /** Absolute floor for pixel absdiff threshold (default 24). */
  absFloor?: number;
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
}

const REF_AREA = 1024 * 1024;

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

function medianMadFromHist(hist: Uint32Array): { median: number; mad: number } {
  let total = 0;
  for (let i = 0; i < hist.length; i++) total += hist[i]!;
  if (total === 0) return { median: 0, mad: 0 };

  const target = (total - 1) / 2;
  let cum = 0;
  let median = 0;
  for (let i = 0; i < hist.length; i++) {
    cum += hist[i]!;
    if (cum > target) {
      median = i;
      break;
    }
  }

  // MAD via second histogram of |v - median|
  const madHist = new Uint32Array(256);
  for (let i = 0; i < hist.length; i++) {
    const d = Math.abs(i - median);
    madHist[d]! += hist[i]!;
  }
  cum = 0;
  let mad = 0;
  for (let i = 0; i < madHist.length; i++) {
    cum += madHist[i]!;
    if (cum > target) {
      mad = i;
      break;
    }
  }
  return { median, mad };
}

interface Component {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
  area: number;
}

/** 8-neighbour connected components on a boolean mask. */
function connectedComponents8(
  mask: Uint8Array,
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
      let minX = x;
      let maxX = x;
      let minY = y;
      let maxY = y;

      while (stack.length > 0) {
        const idx = stack.pop()!;
        area++;
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

      comps.push({ minX, minY, maxX, maxY, area });
    }
  }

  comps.sort((a, b) => b.area - a.area);
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
 * classifier misses. Blurs both images, absdiffs, thresholds with a robust
 * noise floor, then finds 8-neighbour components.
 */
export async function detectLocalizedPixelTamper(
  original: PixelBuffer,
  upload: PixelBuffer,
  options: PixelDiffOptions = {},
): Promise<PixelDiffResult> {
  const outlierK = options.outlierK ?? 6;
  // Floor 12 (not 24): a +15 luma patch after 3×3 blur sits ~12–18; 24 missed
  // copy-region+JPEG cases. JPEG/resize FPs are handled by the mask-fraction gate.
  const absFloor = options.absFloor ?? 12;
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
    };
  }

  const downO = await downscaleIfNeeded(original, maxLongSide);
  const downU = await downscaleIfNeeded(upload, maxLongSide);
  // Same source aspect → same working size; if not, use original's scale path only
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

  const grayO = blur3x3(toGray(workO), w, h);
  const grayU = blur3x3(toGray(workU), w, h);

  const hist = new Uint32Array(256);
  const diffs = new Uint8Array(w * h);
  for (let i = 0; i < w * h; i++) {
    const d = Math.min(255, Math.round(Math.abs(grayO[i]! - grayU[i]!)));
    diffs[i] = d;
    hist[d]!++;
  }

  const { median, mad } = medianMadFromHist(hist);
  const threshold = Math.max(median + outlierK * mad * 1.4826, absFloor);

  const mask = new Uint8Array(w * h);
  let maskCount = 0;
  for (let i = 0; i < w * h; i++) {
    if (diffs[i]! >= threshold) {
      mask[i] = 1;
      maskCount++;
    }
  }

  const workArea = w * h;
  // Resize/re-encode creates widespread structured bands (often ≳7–15%).
  // Allow up to 10% so 128×128 patches (~1.6%) and 64² fixture edits (~6%)
  // still count. GLOBAL_ADJUSTMENT skips this stage in verify for full-frame shifts.
  const maskFraction = maskCount / workArea;
  if (maskFraction > 0.1) {
    return {
      tampered: false,
      reason: `Pixel diffs look global (mask ${(maskFraction * 100).toFixed(2)}% > 10%); not localized`,
      regions: [],
      workingWidth: w,
      workingHeight: h,
      threshold,
    };
  }

  const minArea = Math.max(
    1,
    Math.round(minAreaRef * (workArea / REF_AREA)),
  );

  const comps = connectedComponents8(mask, w, h).filter(
    (c) => c.area >= minArea,
  );

  const regions: LocalizedRegion[] = comps.map((c) => ({
    x: Math.round(c.minX * scaleBack),
    y: Math.round(c.minY * scaleBack),
    width: Math.round((c.maxX - c.minX + 1) * scaleBack),
    height: Math.round((c.maxY - c.minY + 1) * scaleBack),
    area: Math.round(c.area * scaleBack * scaleBack),
  }));

  if (regions.length > 0) {
    return {
      tampered: true,
      reason: `Pixel-level region(s) differ (largest area=${regions[0]!.area}px, threshold=${threshold.toFixed(1)})`,
      regions,
      workingWidth: w,
      workingHeight: h,
      threshold,
    };
  }

  return {
    tampered: false,
    reason: `No localized pixel regions above area ${minArea} (threshold=${threshold.toFixed(1)})`,
    regions: [],
    workingWidth: w,
    workingHeight: h,
    threshold,
  };
}
