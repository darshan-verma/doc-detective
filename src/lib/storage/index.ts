import { getConfig } from "../config";
import { LocalDiskStorage } from "./local-disk";
import type { StorageProvider } from "./types";

export type { StorageProvider } from "./types";
export { LocalDiskStorage } from "./local-disk";

let storage: StorageProvider | null = null;

export function getStorage(): StorageProvider {
  if (!storage) {
    storage = new LocalDiskStorage(getConfig().storageDir);
  }
  return storage;
}

/** Override storage (tests). */
export function setStorage(provider: StorageProvider | null): void {
  storage = provider;
}
