import { getConfig } from "../config";
import { LocalDiskStorage } from "./local-disk";
import { VercelBlobStorage } from "./vercel-blob";
import type { StorageProvider } from "./types";

export type { StorageProvider } from "./types";
export { LocalDiskStorage } from "./local-disk";
export { VercelBlobStorage } from "./vercel-blob";

let storage: StorageProvider | null = null;

function createStorage(): StorageProvider {
  const config = getConfig();
  const provider = config.storageProvider;
  if (provider === "blob") {
    return new VercelBlobStorage();
  }
  if (provider === "local") {
    return new LocalDiskStorage(config.storageDir);
  }
  // auto: prefer Blob when a token is configured (Vercel / local after env pull)
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    return new VercelBlobStorage();
  }
  return new LocalDiskStorage(config.storageDir);
}

export function getStorage(): StorageProvider {
  if (!storage) {
    storage = createStorage();
  }
  return storage;
}

/** Override storage (tests). */
export function setStorage(provider: StorageProvider | null): void {
  storage = provider;
}
