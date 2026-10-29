import { dct2d } from "./dct";
import type { PixelBuffer } from "./pixels";
import { lumaAt, resizeGrayscale } from "./pixels";

export interface CellSignature {
  /** 64-bit difference hash as hex */
  dHash: string;
  /** Mean luminance quantized to 0–255 */
  meanLuma: number;
}

export interface ChangedCellDetail {
  x: number;
  y: number;
  ham: number;
  lumaDelta: number;
  /** ham/64 + lumaDelta/255 */
  cellScore: number;
}

export interface ChangedCellCluster {
  /** Cell coordinates in this connected component (4-neighbour). */
  cells: Array<{ x: number; y: number }>;
  size: number;
  /** Sum of per-cell scores in the cluster. */
  score: number;
}

export interface CellCompareResult {
  changedCells: Array<{ x: number; y: number }>;
  /** Per-changed-cell detail (same order as changedCells). */
  cellDetails: ChangedCellDetail[];
  /** Max cellScore among changed cells (0 if none). */
  maxCellScore: number;
  /** Connected components of changed cells (4-neighbour flood fill). */
  clusters: ChangedCellCluster[];
  changedPercent: number;
  tamperScore: number;
  gridSize: number;
  /** Average Hamming distance across all cells (0–64) */
  visualDistance: number;
}

export type ImageChangeClass =
  | "UNCHANGED"
  | "REENCODED"
  | "GLOBAL_ADJUSTMENT"
  | "TAMPERED";

export interface ClassifyImageChangeConfig {
  tamperScoreAlert?: number;
  cellStrongHamming?: number;
  cellStrongLuma?: number;
  tamperMinClusterCells?: number;
  globalChangeMinPercent?: number;
  /** Std-dev of lumaDelta among changed cells below this → consistent global shift. */
  globalLumaStdMax?: number;
}

export interface ClassifyImageChangeResult {
  classification: ImageChangeClass;
  reason: string;
}

function bitsToHex64(bits: number[]): string {
  let hex = "";
  for (let i = 0; i < 64; i += 4) {
    const nibble =
      ((bits[i]! & 1) << 3) |
      ((bits[i + 1]! & 1) << 2) |
      ((bits[i + 2]! & 1) << 1) |
      (bits[i + 3]! & 1);
    hex += nibble.toString(16);
  }
  return hex;
}

function hexToBits64(hex: string): number[] {
  const bits: number[] = [];
  const h = hex.padStart(16, "0").slice(0, 16);
  for (const ch of h) {
    const n = parseInt(ch, 16);
    bits.push((n >> 3) & 1, (n >> 2) & 1, (n >> 1) & 1, n & 1);
  }
  return bits;
}

/** Hamming distance between two 64-bit hex strings (or bit arrays). */
export function hamming(a: string, b: string): number {
  const ba = hexToBits64(a);
  const bb = hexToBits64(b);
  let d = 0;
  for (let i = 0; i < 64; i++) {
    if (ba[i] !== bb[i]) d++;
  }
  return d;
}

/**
 * Perceptual hash: 32×32 grayscale → DCT → top-left 8×8 (excl DC optional)
 * → median threshold → 64 bits as hex.
 */
export function phash64(pixels: PixelBuffer): string {
  const gray = resizeGrayscale(pixels, 32, 32);
  // Level-shift
  const shifted = new Float64Array(32 * 32);
  for (let i = 0; i < gray.length; i++) shifted[i] = gray[i]! - 128;
  const coeffs = dct2d(shifted, 32);

  // Top-left 8×8 excluding DC (0,0) — use 8×8 including DC then median of 64
  const low: number[] = [];
  for (let v = 0; v < 8; v++) {
    for (let u = 0; u < 8; u++) {
      low.push(coeffs[v * 32 + u]!);
    }
  }
  const sorted = [...low].sort((a, b) => a - b);
  const median = (sorted[31]! + sorted[32]!) / 2;
  const bits = low.map((c) => (c > median ? 1 : 0));
  return bitsToHex64(bits);
}

/** Difference hash for a rectangular region (→ 64-bit hex). */
export function dHashRegion(
  pixels: PixelBuffer,
  x0: number,
  y0: number,
  w: number,
  h: number,
): string {
  // Standard dHash: 9×8 grayscale, compare horizontal neighbors → 8×8 bits
  const gw = 9;
  const gh = 8;
  const grid = new Float64Array(gw * gh);
  for (let y = 0; y < gh; y++) {
    for (let x = 0; x < gw; x++) {
      const sx = x0 + ((x + 0.5) * w) / gw;
      const sy = y0 + ((y + 0.5) * h) / gh;
      const ix = Math.max(0, Math.min(pixels.width - 1, Math.floor(sx)));
      const iy = Math.max(0, Math.min(pixels.height - 1, Math.floor(sy)));
      grid[y * gw + x] = lumaAt(pixels, ix, iy);
    }
  }
  const bits: number[] = [];
  for (let y = 0; y < gh; y++) {
    for (let x = 0; x < 8; x++) {
      bits.push(grid[y * gw + x]! < grid[y * gw + x + 1]! ? 1 : 0);
    }
  }
  return bitsToHex64(bits);
}

function meanLumaRegion(
  pixels: PixelBuffer,
  x0: number,
  y0: number,
  w: number,
  h: number,
): number {
  let sum = 0;
  let count = 0;
  const x1 = Math.min(pixels.width, x0 + w);
  const y1 = Math.min(pixels.height, y0 + h);
  // Subsample for speed on large cells
  const stepX = Math.max(1, Math.floor(w / 16));
  const stepY = Math.max(1, Math.floor(h / 16));
  for (let y = y0; y < y1; y += stepY) {
    for (let x = x0; x < x1; x += stepX) {
      sum += lumaAt(pixels, x, y);
      count++;
    }
  }
  return count === 0 ? 0 : Math.round(sum / count);
}

/**
 * Split image into gridSize × gridSize cells; per cell store dHash + mean luma.
 */
export function cellSignatures(
  pixels: PixelBuffer,
  gridSize: number,
): CellSignature[] {
  const cells: CellSignature[] = [];
  const cellW = pixels.width / gridSize;
  const cellH = pixels.height / gridSize;
  for (let gy = 0; gy < gridSize; gy++) {
    for (let gx = 0; gx < gridSize; gx++) {
      const x0 = Math.floor(gx * cellW);
      const y0 = Math.floor(gy * cellH);
      const x1 = Math.floor((gx + 1) * cellW);
      const y1 = Math.floor((gy + 1) * cellH);
      const w = Math.max(1, x1 - x0);
      const h = Math.max(1, y1 - y0);
      cells.push({
        dHash: dHashRegion(pixels, x0, y0, w, h),
        meanLuma: meanLumaRegion(pixels, x0, y0, w, h),
      });
    }
  }
  return cells;
}

export interface CompareCellsOptions {
  hammingThreshold?: number;
  lumaDeltaThreshold?: number;
}

/** 4-neighbour connected components over changed cell coordinates. */
function clusterChangedCells(
  details: ChangedCellDetail[],
): ChangedCellCluster[] {
  if (details.length === 0) return [];

  const key = (x: number, y: number) => `${x},${y}`;
  const byKey = new Map<string, ChangedCellDetail>();
  for (const d of details) byKey.set(key(d.x, d.y), d);

  const visited = new Set<string>();
  const clusters: ChangedCellCluster[] = [];
  const dirs: Array<[number, number]> = [
    [1, 0],
    [-1, 0],
    [0, 1],
    [0, -1],
  ];

  for (const start of details) {
    const startKey = key(start.x, start.y);
    if (visited.has(startKey)) continue;

    const stack: ChangedCellDetail[] = [start];
    visited.add(startKey);
    const members: ChangedCellDetail[] = [];

    while (stack.length > 0) {
      const cur = stack.pop()!;
      members.push(cur);
      for (const [dx, dy] of dirs) {
        const nk = key(cur.x + dx, cur.y + dy);
        if (visited.has(nk)) continue;
        const neighbor = byKey.get(nk);
        if (!neighbor) continue;
        visited.add(nk);
        stack.push(neighbor);
      }
    }

    clusters.push({
      cells: members.map((m) => ({ x: m.x, y: m.y })),
      size: members.length,
      score: members.reduce((s, m) => s + m.cellScore, 0),
    });
  }

  clusters.sort((a, b) => b.size - a.size || b.score - a.score);
  return clusters;
}

function sampleStdDev(values: number[]): number {
  if (values.length === 0) return 0;
  if (values.length === 1) return 0;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  let sumSq = 0;
  for (const v of values) {
    const d = v - mean;
    sumSq += d * d;
  }
  return Math.sqrt(sumSq / (values.length - 1));
}

/**
 * Compare cell signatures. Returns changed cells (hamming above threshold
 * OR mean luminance delta above threshold), changedPercent, tamperScore,
 * plus per-cell detail, maxCellScore, and connected clusters.
 */
export function compareCells(
  orig: CellSignature[],
  upload: CellSignature[],
  gridSize: number,
  options: CompareCellsOptions = {},
): CellCompareResult {
  const hamThresh = options.hammingThreshold ?? 12;
  const lumaThresh = options.lumaDeltaThreshold ?? 18;
  const n = Math.min(orig.length, upload.length, gridSize * gridSize);
  const changedCells: Array<{ x: number; y: number }> = [];
  const cellDetails: ChangedCellDetail[] = [];
  let hamSum = 0;
  let scoreAccum = 0;
  let maxCellScore = 0;

  for (let i = 0; i < n; i++) {
    const o = orig[i]!;
    const u = upload[i]!;
    const ham = hamming(o.dHash, u.dHash);
    const lumaDelta = Math.abs(o.meanLuma - u.meanLuma);
    hamSum += ham;
    const changed = ham > hamThresh || lumaDelta > lumaThresh;
    if (changed) {
      const x = i % gridSize;
      const y = Math.floor(i / gridSize);
      const cellScore = ham / 64 + lumaDelta / 255;
      changedCells.push({ x, y });
      cellDetails.push({ x, y, ham, lumaDelta, cellScore });
      scoreAccum += cellScore;
      if (cellScore > maxCellScore) maxCellScore = cellScore;
    }
  }

  const total = gridSize * gridSize;
  const changedPercent = total === 0 ? 0 : (changedCells.length / total) * 100;
  const visualDistance = n === 0 ? 0 : hamSum / n;
  // tamperScore: scales with how many cells changed and how strongly
  const tamperScore =
    changedCells.length === 0
      ? 0
      : (changedPercent / 100) *
        (1 + scoreAccum / Math.max(1, changedCells.length)) *
        10;

  const clusters = clusterChangedCells(cellDetails);

  return {
    changedCells,
    cellDetails,
    maxCellScore,
    clusters,
    changedPercent,
    tamperScore,
    gridSize,
    visualDistance,
  };
}

/**
 * Decide whether cell-level differences look like noise, a global filter,
 * or localized tampering. Pure function — no I/O.
 *
 * Evaluation order:
 * 1. UNCHANGED — no changed cells
 * 2. strong single-cell (a) → TAMPERED
 * 3. GLOBAL_ADJUSTMENT (before cluster rule — global filters touch many adjacent cells)
 * 4. connected cluster size (b) → TAMPERED
 * 5. legacy global tamperScore (c) → TAMPERED
 * 6. otherwise REENCODED
 */
export function classifyImageChange(
  result: CellCompareResult,
  cfg: ClassifyImageChangeConfig = {},
): ClassifyImageChangeResult {
  const tamperScoreAlert = cfg.tamperScoreAlert ?? 1.5;
  // See config.ts CELL_STRONG_HAMMING — 48 avoids brightness/resize false TAMPERED.
  const cellStrongHamming = cfg.cellStrongHamming ?? 48;
  const cellStrongLuma = cfg.cellStrongLuma ?? 40;
  const tamperMinClusterCells = cfg.tamperMinClusterCells ?? 2;
  const globalChangeMinPercent = cfg.globalChangeMinPercent ?? 60;
  const globalLumaStdMax = cfg.globalLumaStdMax ?? 8;

  if (result.changedCells.length === 0) {
    return { classification: "UNCHANGED", reason: "No changed cells" };
  }

  const strong = result.cellDetails.find(
    (c) => c.ham > cellStrongHamming || c.lumaDelta > cellStrongLuma,
  );
  if (strong) {
    return {
      classification: "TAMPERED",
      reason: `Strong cell change at (${strong.x},${strong.y}): ham=${strong.ham}, lumaDelta=${strong.lumaDelta}`,
    };
  }

  // Global brightness/contrast/filter: many cells, consistent luma shift, no strong cells.
  // Checked before cluster size so a whole-image adjustment is not called TAMPERED.
  if (result.changedPercent > globalChangeMinPercent) {
    const lumaStd = sampleStdDev(result.cellDetails.map((c) => c.lumaDelta));
    if (lumaStd < globalLumaStdMax) {
      return {
        classification: "GLOBAL_ADJUSTMENT",
        reason: `${result.changedPercent.toFixed(1)}% of cells changed with consistent lumaDelta (std=${lumaStd.toFixed(2)}); likely brightness/contrast/filter`,
      };
    }
  }

  const largeCluster = result.clusters.find(
    (c) => c.size >= tamperMinClusterCells,
  );
  if (largeCluster) {
    return {
      classification: "TAMPERED",
      reason: `Connected cluster of ${largeCluster.size} changed cell(s) (score=${largeCluster.score.toFixed(2)})`,
    };
  }

  if (result.tamperScore >= tamperScoreAlert) {
    return {
      classification: "TAMPERED",
      reason: `Global tamperScore ${result.tamperScore.toFixed(2)} >= alert ${tamperScoreAlert}`,
    };
  }

  return {
    classification: "REENCODED",
    reason: `Isolated weak cell noise (${result.changedCells.length} cell(s), score=${result.tamperScore.toFixed(2)})`,
  };
}
