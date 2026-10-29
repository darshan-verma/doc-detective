/**
 * Noise-adaptive cell outliers + pixel second-stage (pure — no DB).
 *
 * Defaults (zod / getConfig SSOT — do not hard-code classifier literals here):
 * - CELL_STRONG_HAMMING=48, CELL_STRONG_LUMA=40
 * - OUTLIER_K=6, OUTLIER_ABS_FLOOR=0.15, MAD floor 0.02 — JPEG q70 stays under
 *   the outlier bar; MAD=0 uniform shifts no longer flood outliers.
 * - PIXEL_MIN_REGION_AREA=80 at 1024²; pixel absFloor=12; mask-fraction gate 10%
 *   — catches 24–32px erasures and +15 copy-regions without JPEG/resize FPs.
 * - TAMPER_MIN_CLUSTER_CELLS=2, GLOBAL_CHANGE_MIN_PERCENT=60
 *
 * Tune K / floors (not these assertions) if a case fails.
 */
import path from "path";
import { readFile } from "fs/promises";
import { generateKeyPairSync } from "crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import sharp from "sharp";
import { getConfig, resetConfigCache } from "../src/lib/config";
import {
  cellSignatures,
  classifyImageChange,
  compareCells,
  decodeImage,
  detectLocalizedPixelTamper,
  encodeJpeg,
} from "../src/lib/image";
import type { PixelBuffer } from "../src/lib/image/pixels";
import type { ImageChangeClass } from "../src/lib/image";

const TUNABLE_ENV = [
  "CELL_STRONG_HAMMING",
  "CELL_STRONG_LUMA",
  "CELL_HAMMING_THRESHOLD",
  "CELL_LUMA_DELTA_THRESHOLD",
  "TAMPER_SCORE_ALERT",
  "TAMPER_MIN_CLUSTER_CELLS",
  "GLOBAL_CHANGE_MIN_PERCENT",
  "OUTLIER_K",
  "OUTLIER_ABS_FLOOR",
  "PIXEL_MIN_REGION_AREA",
  "IMAGE_GRID_SIZE",
] as const;

const savedEnv: Record<string, string | undefined> = {};

beforeAll(() => {
  for (const k of TUNABLE_ENV) {
    savedEnv[k] = process.env[k];
    delete process.env[k];
  }
  if (!process.env.ED25519_PRIVATE_KEY) {
    const { privateKey } = generateKeyPairSync("ed25519");
    process.env.ED25519_PRIVATE_KEY = privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();
  }
  if (!process.env.DATABASE_URL) {
    process.env.DATABASE_URL = "file:./prisma/dev.db";
  }
  resetConfigCache();
});

afterAll(() => {
  for (const k of TUNABLE_ENV) {
    const v = savedEnv[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  resetConfigCache();
});

function cfg() {
  return getConfig();
}

function classifyOpts() {
  const c = cfg();
  return {
    tamperScoreAlert: c.tamperScoreAlert,
    cellStrongHamming: c.cellStrongHamming,
    cellStrongLuma: c.cellStrongLuma,
    tamperMinClusterCells: c.tamperMinClusterCells,
    globalChangeMinPercent: c.globalChangeMinPercent,
    outlierK: c.outlierK,
    outlierAbsFloor: c.outlierAbsFloor,
  };
}

function compareOpts() {
  const c = cfg();
  return {
    hammingThreshold: c.cellHammingThreshold,
    lumaDeltaThreshold: c.cellLumaDeltaThreshold,
    outlierK: c.outlierK,
    outlierAbsFloor: c.outlierAbsFloor,
  };
}

/** Mirrors verifyImageAgainstCert cell + pixel stages (no DB). */
async function fullVerdict(
  orig: PixelBuffer,
  next: PixelBuffer,
): Promise<{ classification: ImageChangeClass; via: "cell" | "pixel" }> {
  const grid = cfg().imageGridSize;
  const cmp = compareCells(
    cellSignatures(orig, grid),
    cellSignatures(next, grid),
    grid,
    compareOpts(),
  );
  const cell = classifyImageChange(cmp, classifyOpts());
  if (cell.classification === "TAMPERED") {
    return { classification: "TAMPERED", via: "cell" };
  }
  // Match verifyImageAgainstCert: skip pixel stage on GLOBAL_ADJUSTMENT.
  if (cell.classification === "GLOBAL_ADJUSTMENT") {
    return { classification: cell.classification, via: "cell" };
  }
  const pixel = await detectLocalizedPixelTamper(orig, next, {
    minRegionArea: cfg().pixelMinRegionArea,
    outlierK: cfg().outlierK,
  });
  if (pixel.tampered) {
    return { classification: "TAMPERED", via: "pixel" };
  }
  return { classification: cell.classification, via: "cell" };
}

async function fromRgb(raw: Buffer, size: number): Promise<PixelBuffer> {
  const png = await sharp(raw, {
    raw: { width: size, height: size, channels: 3 },
  })
    .png()
    .toBuffer();
  return decodeImage(png);
}

/** (i) Existing smooth document: light page + dark horizontal stripes. */
async function smoothDocument(size = 1024): Promise<PixelBuffer> {
  const raw = Buffer.alloc(size * size * 3);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 3;
      const stripe = y % 48 < 10 && x > 64 && x < size - 64;
      const v = stripe ? 28 + ((x + y) % 12) : 242 - ((x * 3 + y) % 8);
      raw[i] = v;
      raw[i + 1] = v;
      raw[i + 2] = v;
    }
  }
  return fromRgb(raw, size);
}

/** (ii) Harsher text-like page (JPEG-sensitive). */
async function harshTextPage(size = 1024): Promise<PixelBuffer> {
  const raw = Buffer.alloc(size * size * 3);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 3;
      const dark =
        y % 40 < 12 && ((x * 7 + y * 3) % 23) < 14;
      const v = dark ? 30 : 245;
      raw[i] = v;
      raw[i + 1] = v;
      raw[i + 2] = v;
    }
  }
  return fromRgb(raw, size);
}

/** (iii) Photo-like: sinusoids + seeded noise. */
async function photoLike(size = 1024, seed = 42): Promise<PixelBuffer> {
  let s = seed >>> 0;
  const rand = () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 0x100000000;
  };
  const raw = Buffer.alloc(size * size * 3);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 3;
      const noise = (rand() * 20) - 10;
      const v = Math.max(
        0,
        Math.min(
          255,
          128 + 60 * Math.sin(x / 90) + 40 * Math.cos(y / 70) + noise,
        ),
      );
      raw[i] = v;
      raw[i + 1] = v * 0.9;
      raw[i + 2] = v * 0.8;
    }
  }
  return fromRgb(raw, size);
}

function overwriteBlock(
  pixels: PixelBuffer,
  x0: number,
  y0: number,
  block: number,
  rgb: [number, number, number] = [12, 12, 12],
): PixelBuffer {
  const out: PixelBuffer = {
    data: new Uint8ClampedArray(pixels.data),
    width: pixels.width,
    height: pixels.height,
  };
  for (let y = y0; y < y0 + block && y < out.height; y++) {
    for (let x = x0; x < x0 + block && x < out.width; x++) {
      const i = (y * out.width + x) * 4;
      out.data[i] = rgb[0];
      out.data[i + 1] = rgb[1];
      out.data[i + 2] = rgb[2];
    }
  }
  return out;
}

function addBrightness(pixels: PixelBuffer, delta: number): PixelBuffer {
  const out: PixelBuffer = {
    data: new Uint8ClampedArray(pixels.data),
    width: pixels.width,
    height: pixels.height,
  };
  for (let i = 0; i < out.data.length; i += 4) {
    out.data[i] = Math.max(0, Math.min(255, out.data[i]! + delta));
    out.data[i + 1] = Math.max(0, Math.min(255, out.data[i + 1]! + delta));
    out.data[i + 2] = Math.max(0, Math.min(255, out.data[i + 2]! + delta));
  }
  return out;
}

/** Copy a region from elsewhere, then +15 brightness on that patch. */
function copyRegionBrighten(
  pixels: PixelBuffer,
  dstX: number,
  dstY: number,
  srcX: number,
  srcY: number,
  size: number,
  brighten = 15,
): PixelBuffer {
  const out: PixelBuffer = {
    data: new Uint8ClampedArray(pixels.data),
    width: pixels.width,
    height: pixels.height,
  };
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const si = ((srcY + y) * out.width + (srcX + x)) * 4;
      const di = ((dstY + y) * out.width + (dstX + x)) * 4;
      out.data[di] = Math.min(255, pixels.data[si]! + brighten);
      out.data[di + 1] = Math.min(255, pixels.data[si + 1]! + brighten);
      out.data[di + 2] = Math.min(255, pixels.data[si + 2]! + brighten);
    }
  }
  return out;
}

async function resize50ThenUp(orig: PixelBuffer): Promise<PixelBuffer> {
  const half = await sharp(Buffer.from(orig.data), {
    raw: { width: orig.width, height: orig.height, channels: 4 },
  })
    .resize(Math.round(orig.width / 2), Math.round(orig.height / 2))
    .raw()
    .toBuffer({ resolveWithObject: true });
  const back = await sharp(half.data, {
    raw: { width: half.info.width, height: half.info.height, channels: 4 },
  })
    .resize(orig.width, orig.height)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  return {
    data: new Uint8ClampedArray(back.data),
    width: orig.width,
    height: orig.height,
  };
}

const SOURCES: Array<{
  name: string;
  build: () => Promise<PixelBuffer>;
}> = [
  { name: "smooth", build: () => smoothDocument(1024) },
  { name: "harsh-text", build: () => harshTextPage(1024) },
  { name: "photo", build: () => photoLike(1024) },
];

describe("config defaults (zod SSOT)", () => {
  it("getConfig().cellStrongHamming === 48 when env unset", () => {
    expect(process.env.CELL_STRONG_HAMMING).toBeUndefined();
    resetConfigCache();
    expect(getConfig().cellStrongHamming).toBe(48);
    expect(getConfig().outlierK).toBe(6);
    expect(getConfig().outlierAbsFloor).toBe(0.15);
    expect(getConfig().pixelMinRegionArea).toBe(80);
  });
});

describe.each(SOURCES)("tamper pipeline — $name", ({ build }) => {
  it.each([95, 85, 70])(
    "JPEG q%i re-encode → NOT TAMPERED",
    async (q) => {
      const orig = await build();
      const decoded = await decodeImage(await encodeJpeg(orig, q));
      const { classification } = await fullVerdict(orig, decoded);
      expect(classification).not.toBe("TAMPERED");
    },
  );

  it("50% down + up resize → NOT TAMPERED", async () => {
    const orig = await build();
    const back = await resize50ThenUp(orig);
    const { classification } = await fullVerdict(orig, back);
    expect(classification).not.toBe("TAMPERED");
  });

  it("brightness +20 → NOT TAMPERED", async () => {
    const orig = await build();
    const bright = addBrightness(orig, 20);
    const { classification } = await fullVerdict(orig, bright);
    expect(classification).not.toBe("TAMPERED");
  });

  it.each([64, 128, 192, 320])(
    "block overwrite %ipx → TAMPERED",
    async (block) => {
      const orig = await build();
      const edited = overwriteBlock(orig, 200, 200, block);
      const { classification } = await fullVerdict(orig, edited);
      expect(classification).toBe("TAMPERED");
    },
  );

  it("128px copy+15 brightness then JPEG q80 → TAMPERED", async () => {
    const orig = await build();
    const edited = copyRegionBrighten(orig, 100, 100, 500, 500, 128, 15);
    const jpeg = await decodeImage(await encodeJpeg(edited, 80));
    const { classification } = await fullVerdict(orig, jpeg);
    expect(classification).toBe("TAMPERED");
  });
});

describe("sub-cell patches (harsh text + pixel stage)", () => {
  it.each([24, 32])(
    "%ipx patch inside one cell → TAMPERED via pixel stage",
    async (patch) => {
      const orig = await harshTextPage(1024);
      // Cell (0,0) is [0,32)×[0,32) on a 32-grid / 1024 image.
      const edited = overwriteBlock(orig, 4, 4, patch, [250, 250, 250]);
      const result = await fullVerdict(orig, edited);
      expect(result.classification).toBe("TAMPERED");
      // 32px fills one whole cell and may trip the cell stage; 24px should need pixels.
      if (patch < 32) expect(result.via).toBe("pixel");
    },
  );
});

describe("corpus fixtures", () => {
  const fixtures = path.join(process.cwd(), "tests/corpus/fixtures");

  it("dot.png vs dot-reencoded.png → NOT TAMPERED", async () => {
    const a = await decodeImage(await readFile(path.join(fixtures, "dot.png")));
    const b = await decodeImage(
      await readFile(path.join(fixtures, "dot-reencoded.png")),
    );
    const { classification } = await fullVerdict(a, b);
    expect(classification).not.toBe("TAMPERED");
  });

  it("dot.png vs dot-edited.png → TAMPERED", async () => {
    const a = await decodeImage(await readFile(path.join(fixtures, "dot.png")));
    const b = await decodeImage(
      await readFile(path.join(fixtures, "dot-edited.png")),
    );
    const { classification } = await fullVerdict(a, b);
    expect(classification).toBe("TAMPERED");
  });
});
