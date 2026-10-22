import { createHash } from "crypto";
import { createReadStream } from "fs";
import { Readable } from "stream";
import { CHUNK_SIZE } from "./config";

export interface HashResult {
  sha256: string;
  sizeBytes: number;
  chunkHashes: string[];
}

/**
 * Stream a Node Readable through SHA-256 and per-chunk hashes.
 * Never buffers the whole file in memory.
 */
export async function hashStream(stream: Readable): Promise<HashResult> {
  const fileHash = createHash("sha256");
  const chunkHashes: string[] = [];
  let sizeBytes = 0;
  let pending = Buffer.alloc(0);

  for await (const chunk of stream) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    fileHash.update(buf);
    sizeBytes += buf.length;

    pending = Buffer.concat([pending, buf]);
    while (pending.length >= CHUNK_SIZE) {
      const block = pending.subarray(0, CHUNK_SIZE);
      chunkHashes.push(createHash("sha256").update(block).digest("hex"));
      pending = pending.subarray(CHUNK_SIZE);
    }
  }

  if (pending.length > 0) {
    chunkHashes.push(createHash("sha256").update(pending).digest("hex"));
  }

  return {
    sha256: fileHash.digest("hex"),
    sizeBytes,
    chunkHashes,
  };
}

/** Hash a file on disk via streaming. */
export async function hashFile(path: string): Promise<HashResult> {
  return hashStream(createReadStream(path));
}

/** Hash a Buffer (for small in-memory test fixtures only). */
export async function hashBuffer(data: Buffer): Promise<HashResult> {
  return hashStream(Readable.from([data]));
}

/**
 * Tee an incoming Web ReadableStream into (1) a Node writable sink via
 * async iterator and (2) return hash + size while writing chunks.
 * Used when we need to both store and hash without loading whole file.
 */
export async function hashAndCollectChunks(
  webStream: ReadableStream<Uint8Array>,
  onChunk: (chunk: Buffer) => Promise<void> | void,
): Promise<HashResult> {
  const fileHash = createHash("sha256");
  const chunkHashes: string[] = [];
  let sizeBytes = 0;
  let pending = Buffer.alloc(0);

  const reader = webStream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const buf = Buffer.from(value);
      fileHash.update(buf);
      sizeBytes += buf.length;
      await onChunk(buf);

      pending = Buffer.concat([pending, buf]);
      while (pending.length >= CHUNK_SIZE) {
        const block = pending.subarray(0, CHUNK_SIZE);
        chunkHashes.push(createHash("sha256").update(block).digest("hex"));
        pending = pending.subarray(CHUNK_SIZE);
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (pending.length > 0) {
    chunkHashes.push(createHash("sha256").update(pending).digest("hex"));
  }

  return {
    sha256: fileHash.digest("hex"),
    sizeBytes,
    chunkHashes,
  };
}
