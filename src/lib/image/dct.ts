/** Orthornormal 2D DCT-II / IDCT for N×N blocks (typically 8). */

function alpha(u: number, n: number): number {
  return u === 0 ? Math.SQRT1_2 : 1;
}

/** Forward DCT-II: spatial → frequency. */
export function dct2d(block: Float64Array, n = 8): Float64Array {
  const out = new Float64Array(n * n);
  const scale = 2 / n;
  for (let u = 0; u < n; u++) {
    for (let v = 0; v < n; v++) {
      let sum = 0;
      for (let x = 0; x < n; x++) {
        for (let y = 0; y < n; y++) {
          sum +=
            block[y * n + x]! *
            Math.cos(((2 * x + 1) * u * Math.PI) / (2 * n)) *
            Math.cos(((2 * y + 1) * v * Math.PI) / (2 * n));
        }
      }
      out[v * n + u] = scale * alpha(u, n) * alpha(v, n) * sum;
    }
  }
  return out;
}

/** Inverse DCT-II: frequency → spatial. */
export function idct2d(coeffs: Float64Array, n = 8): Float64Array {
  const out = new Float64Array(n * n);
  const scale = 2 / n;
  for (let x = 0; x < n; x++) {
    for (let y = 0; y < n; y++) {
      let sum = 0;
      for (let u = 0; u < n; u++) {
        for (let v = 0; v < n; v++) {
          sum +=
            alpha(u, n) *
            alpha(v, n) *
            coeffs[v * n + u]! *
            Math.cos(((2 * x + 1) * u * Math.PI) / (2 * n)) *
            Math.cos(((2 * y + 1) * v * Math.PI) / (2 * n));
        }
      }
      out[y * n + x] = scale * sum;
    }
  }
  return out;
}
