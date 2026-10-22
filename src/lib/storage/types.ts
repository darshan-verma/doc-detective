import type { Readable } from "stream";

export interface StorageProvider {
  /** Persist bytes under key. Overwrites if exists. */
  put(key: string, data: Readable | Buffer): Promise<void>;
  /** Return a readable stream of the stored object. */
  get(key: string): Promise<Readable>;
  exists(key: string): Promise<boolean>;
  /** Absolute or relative path used for local providers (optional). */
  resolvePath?(key: string): string;
}
