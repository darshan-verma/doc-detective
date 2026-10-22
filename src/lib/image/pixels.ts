/** Raw RGBA pixel buffer (row-major, 4 bytes per pixel). */
export interface PixelBuffer {
  data: Uint8ClampedArray;
  width: number;
  height: number;
}

export function clonePixels(pixels: PixelBuffer): PixelBuffer {
  return {
    data: new Uint8ClampedArray(pixels.data),
    width: pixels.width,
    height: pixels.height,
  };
}

export function lumaAt(pixels: PixelBuffer, x: number, y: number): number {
  const i = (y * pixels.width + x) * 4;
  const r = pixels.data[i]!;
  const g = pixels.data[i + 1]!;
  const b = pixels.data[i + 2]!;
  return 0.299 * r + 0.587 * g + 0.114 * b;
}

/** Bilinear sample of grayscale luminance. */
export function sampleLuma(
  pixels: PixelBuffer,
  x: number,
  y: number,
): number {
  const x0 = Math.floor(x);
  const y0 = Math.floor(y);
  const x1 = Math.min(x0 + 1, pixels.width - 1);
  const y1 = Math.min(y0 + 1, pixels.height - 1);
  const fx = x - x0;
  const fy = y - y0;
  const a = lumaAt(pixels, Math.max(0, x0), Math.max(0, y0));
  const b = lumaAt(pixels, x1, Math.max(0, y0));
  const c = lumaAt(pixels, Math.max(0, x0), y1);
  const d = lumaAt(pixels, x1, y1);
  return a * (1 - fx) * (1 - fy) + b * fx * (1 - fy) + c * (1 - fx) * fy + d * fx * fy;
}

export function resizeGrayscale(
  pixels: PixelBuffer,
  outW: number,
  outH: number,
): Float64Array {
  const out = new Float64Array(outW * outH);
  for (let y = 0; y < outH; y++) {
    for (let x = 0; x < outW; x++) {
      const sx = ((x + 0.5) * pixels.width) / outW - 0.5;
      const sy = ((y + 0.5) * pixels.height) / outH - 0.5;
      out[y * outW + x] = sampleLuma(
        pixels,
        Math.max(0, Math.min(pixels.width - 1, sx)),
        Math.max(0, Math.min(pixels.height - 1, sy)),
      );
    }
  }
  return out;
}
