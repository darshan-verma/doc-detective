import { Readable } from "stream";
import {
  BlobNotFoundError,
  get,
  head,
  put,
} from "@vercel/blob";
import type { StorageProvider } from "./types";

/**
 * Private Vercel Blob store. Requires BLOB_READ_WRITE_TOKEN (or OIDC on Vercel).
 * Pathnames are the same storage keys used for Certificate.storagePath.
 */
export class VercelBlobStorage implements StorageProvider {
  private readonly access = "private" as const;

  async put(key: string, data: Readable | Buffer): Promise<void> {
    const pathname = sanitizeKey(key);
    const body = Buffer.isBuffer(data)
      ? data
      : (Readable.toWeb(data) as ReadableStream);

    await put(pathname, body, {
      access: this.access,
      allowOverwrite: true,
      addRandomSuffix: false,
      multipart: true,
    });
  }

  async get(key: string): Promise<Readable> {
    const pathname = sanitizeKey(key);
    const result = await get(pathname, { access: this.access });
    if (!result || result.statusCode !== 200 || !result.stream) {
      throw new BlobNotFoundError();
    }
    return Readable.fromWeb(result.stream as import("stream/web").ReadableStream);
  }

  async exists(key: string): Promise<boolean> {
    try {
      await head(sanitizeKey(key));
      return true;
    } catch (err) {
      if (err instanceof BlobNotFoundError) return false;
      const message = err instanceof Error ? err.message : String(err);
      if (/not found|404/i.test(message)) return false;
      throw err;
    }
  }
}

function sanitizeKey(key: string): string {
  return key.replace(/\.\./g, "").replace(/^\/+/, "");
}
