import type { BoundingBox } from "./types";

/**
 * Cluster mismatched pixels from a pixelmatch RGBA mask into axis-aligned boxes.
 * `diff` is RGBA where non-zero alpha (or red channel) marks a change.
 */
export function boundingBoxesFromDiffMask(
  diff: Uint8Array,
  width: number,
  height: number,
  options?: { cellSize?: number; minCells?: number },
): BoundingBox[] {
  const cell = options?.cellSize ?? 16;
  const minCells = options?.minCells ?? 1;
  const cols = Math.ceil(width / cell);
  const rows = Math.ceil(height / cell);
  const dirty = new Uint8Array(cols * rows);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 4;
      // pixelmatch writes magenta-ish; any non-zero channel counts
      if (diff[i]! || diff[i + 1]! || diff[i + 2]!) {
        const cx = Math.floor(x / cell);
        const cy = Math.floor(y / cell);
        dirty[cy * cols + cx] = 1;
      }
    }
  }

  const visited = new Uint8Array(cols * rows);
  const boxes: BoundingBox[] = [];

  for (let cy = 0; cy < rows; cy++) {
    for (let cx = 0; cx < cols; cx++) {
      const start = cy * cols + cx;
      if (!dirty[start] || visited[start]) continue;

      let minX = cx;
      let maxX = cx;
      let minY = cy;
      let maxY = cy;
      const stack = [start];
      visited[start] = 1;
      let count = 0;

      while (stack.length) {
        const idx = stack.pop()!;
        count++;
        const x = idx % cols;
        const y = Math.floor(idx / cols);
        minX = Math.min(minX, x);
        maxX = Math.max(maxX, x);
        minY = Math.min(minY, y);
        maxY = Math.max(maxY, y);
        for (const [nx, ny] of [
          [x - 1, y],
          [x + 1, y],
          [x, y - 1],
          [x, y + 1],
        ] as const) {
          if (nx < 0 || ny < 0 || nx >= cols || ny >= rows) continue;
          const nidx = ny * cols + nx;
          if (!dirty[nidx] || visited[nidx]) continue;
          visited[nidx] = 1;
          stack.push(nidx);
        }
      }

      if (count < minCells) continue;

      const px = minX * cell;
      const py = minY * cell;
      const pw = Math.min(width, (maxX + 1) * cell) - px;
      const ph = Math.min(height, (maxY + 1) * cell) - py;
      boxes.push({
        x: px / width,
        y: py / height,
        width: pw / width,
        height: ph / height,
        normalized: true,
      });
    }
  }

  return boxes;
}
