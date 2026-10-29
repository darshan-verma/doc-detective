/**
 * Localized tamper classification tests (pure — no DB).
 *
 * Tuned defaults (do not weaken block-edit detection to pass these):
 * - CELL_STRONG_HAMMING=48 (not 20): +20 brightness clamping and 50% down/up resize
 *   produce per-cell ham ~24–40 on textured pages; those must miss rule (a) so
 *   GLOBAL_ADJUSTMENT (changedPercent > 60% + low lumaDelta std) can fire.
 * - CELL_STRONG_LUMA=40, TAMPER_MIN_CLUSTER_CELLS=2, GLOBAL_CHANGE_MIN_PERCENT=60
 * - A 64×64 block edit on 1024×1024 / 32-grid still lights a connected cluster ≥ 2
 *   → TAMPERED via rule (b), independent of the raised strong-hamming default.
 */
import path from "path";
import { readFile } from "fs/promises";
import { describe, expect, it } from "vitest";
import sharp from "sharp";
import {
  cellSignatures,
  classifyImageChange,
  compareCells,
  decodeImage,
  encodeJpeg,
} from "../src/lib/image";
import type { PixelBuffer } from "../src/lib/image/pixels";

const GRID = 32;
const COMPARE_OPTS = { hammingThreshold: 12, lumaDeltaThreshold: 18 };
const CLASSIFY_CFG = {
  tamperScoreAlert: 1.5,
  cellStrongHamming: 48,
  cellStrongLuma: 40,
  tamperMinClusterCells: 2,
  globalChangeMinPercent: 60,
};

/** Synthetic "document": light page + dark text-like horizontal stripes. */
async function syntheticDocument(size = 1024): Promise<PixelBuffer> {
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
  const png = await sharp(raw, { raw: { width: size, height: size, channels: 3 } })
    .png()
    .toBuffer();
  return decodeImage(png);
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

function classifyPair(orig: PixelBuffer, next: PixelBuffer) {
  const a = cellSignatures(orig, GRID);
  const b = cellSignatures(next, GRID);
  const cmp = compareCells(a, b, GRID, COMPARE_OPTS);
  return { cmp, ...classifyImageChange(cmp, CLASSIFY_CFG) };
}

describe("classifyImageChange — synthetic document", () => {
  it.each([64, 128, 192, 320])(
    "block overwrite %ipx → TAMPERED",
    async (block) => {
      const orig = await syntheticDocument(1024);
      const edited = overwriteBlock(orig, 200, 200, block);
      const { classification, cmp } = classifyPair(orig, edited);
      expect(classification).toBe("TAMPERED");
      expect(cmp.changedCells.length).toBeGreaterThan(0);
    },
  );

  it("JPEG quality 85 re-encode → NOT TAMPERED", async () => {
    const orig = await syntheticDocument(1024);
    const jpeg = await encodeJpeg(orig, 85);
    const decoded = await decodeImage(jpeg);
    const { classification } = classifyPair(orig, decoded);
    expect(classification).not.toBe("TAMPERED");
  });

  it("downscale 50% then up → NOT TAMPERED", async () => {
    const orig = await syntheticDocument(1024);
    const half = await sharp(Buffer.from(orig.data), {
      raw: { width: orig.width, height: orig.height, channels: 4 },
    })
      .resize(512, 512)
      .raw()
      .toBuffer({ resolveWithObject: true });
    const backBuf = await sharp(half.data, {
      raw: { width: 512, height: 512, channels: 4 },
    })
      .resize(1024, 1024)
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const back: PixelBuffer = {
      data: new Uint8ClampedArray(backBuf.data),
      width: 1024,
      height: 1024,
    };
    const { classification } = classifyPair(orig, back);
    expect(classification).not.toBe("TAMPERED");
  });

  it("+20 brightness → GLOBAL_ADJUSTMENT (not TAMPERED)", async () => {
    const orig = await syntheticDocument(1024);
    const bright = addBrightness(orig, 20);
    const { classification } = classifyPair(orig, bright);
    expect(classification).toBe("GLOBAL_ADJUSTMENT");
  });
});

describe("classifyImageChange — corpus fixtures", () => {
  const fixtures = path.join(process.cwd(), "tests/corpus/fixtures");

  it("dot.png vs dot-reencoded.png → NOT TAMPERED", async () => {
    const a = await decodeImage(await readFile(path.join(fixtures, "dot.png")));
    const b = await decodeImage(
      await readFile(path.join(fixtures, "dot-reencoded.png")),
    );
    // Fixture images may be small; use their native size with GRID capped by cells.
    const grid = Math.min(GRID, Math.min(a.width, a.height));
    const cmp = compareCells(
      cellSignatures(a, grid),
      cellSignatures(b, grid),
      grid,
      COMPARE_OPTS,
    );
    const { classification } = classifyImageChange(cmp, CLASSIFY_CFG);
    expect(classification).not.toBe("TAMPERED");
  });

  it("dot.png vs dot-edited.png → TAMPERED", async () => {
    const a = await decodeImage(await readFile(path.join(fixtures, "dot.png")));
    const b = await decodeImage(
      await readFile(path.join(fixtures, "dot-edited.png")),
    );
    const grid = Math.min(GRID, Math.min(a.width, a.height));
    const cmp = compareCells(
      cellSignatures(a, grid),
      cellSignatures(b, grid),
      grid,
      COMPARE_OPTS,
    );
    const { classification } = classifyImageChange(cmp, CLASSIFY_CFG);
    expect(classification).toBe("TAMPERED");
  });
});
