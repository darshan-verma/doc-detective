import { getConfig } from "../config";
import { LocalDiskStorage } from "./local-disk";
import { VercelBlobStorage } from "./vercel-blob";
import type { StorageProvider } from "./types";

export type { StorageProvider } from "./types";
export { LocalDiskStorage } from "./local-disk";
export { VercelBlobStorage } from "./vercel-blob";

let storage: StorageProvider | null = null;

function isVercelRuntime(): boolean {
  return process.env.VERCEL === "1" || Boolean(process.env.VERCEL_ENV);
}

function createStorage(): StorageProvider {
  const config = getConfig();
  const provider = config.storageProvider;

  if (provider === "blob") {
    return new VercelBlobStorage();
  }

  if (provider === "local") {
    if (isVercelRuntime()) {
      throw new Error(
        "STORAGE_PROVIDER=local cannot run on Vercel (read-only filesystem). " +
          "Use STORAGE_PROVIDER=blob or auto, and ensure a Blob store is linked.",
      );
    }
    return new LocalDiskStorage(config.storageDir);
  }

  // auto: never use local disk on Vercel — /var/task is read-only
  if (
    isVercelRuntime() ||
    process.env.BLOB_READ_WRITE_TOKEN ||
    process.env.BLOB_STORE_ID
  ) {
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
