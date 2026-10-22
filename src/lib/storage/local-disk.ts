import { createReadStream, createWriteStream, existsSync } from "fs";
import { mkdir, access } from "fs/promises";
import path from "path";
import { pipeline } from "stream/promises";
import type { Readable } from "stream";
import { Readable as NodeReadable } from "stream";
import type { StorageProvider } from "./types";

export class LocalDiskStorage implements StorageProvider {
  constructor(private readonly rootDir: string) {}

  resolvePath(key: string): string {
    const safe = key.replace(/\.\./g, "").replace(/^\/+/, "");
    const full = path.resolve(this.rootDir, safe);
    const root = path.resolve(this.rootDir);
    if (!full.startsWith(root + path.sep) && full !== root) {
      throw new Error("Invalid storage key (path traversal)");
    }
    return full;
  }

  private async ensureRoot(): Promise<void> {
    await mkdir(this.rootDir, { recursive: true });
  }

  async put(key: string, data: Readable | Buffer): Promise<void> {
    await this.ensureRoot();
    const dest = this.resolvePath(key);
    await mkdir(path.dirname(dest), { recursive: true });
    const stream = Buffer.isBuffer(data)
      ? NodeReadable.from([data])
      : data;
    await pipeline(stream, createWriteStream(dest));
  }

  async get(key: string): Promise<Readable> {
    const dest = this.resolvePath(key);
    return createReadStream(dest);
  }

  async exists(key: string): Promise<boolean> {
    try {
      await access(this.resolvePath(key));
      return true;
    } catch {
      return existsSync(this.resolvePath(key));
    }
  }
}
