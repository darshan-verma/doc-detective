import { createPrivateKey, createPublicKey } from "crypto";
import { z } from "zod";

/**
 * PKCS8 body of the old committed example key. Production must not use a key
 * whose public key matches this material.
 */
const EXAMPLE_ED25519_PKCS8_B64 =
  "MC4CAQAwBQYDK2VwBCIEILSEi4GERcJZPSR6zKIGi7uDvsuILLlPf++AU+f/MiFY";

function publicKeyDerFromPrivatePemOrB64(raw: string): Buffer {
  const trimmed = raw.trim().replace(/\\n/g, "\n");
  const priv = trimmed.includes("BEGIN")
    ? createPrivateKey(trimmed)
    : createPrivateKey({
        key: Buffer.from(trimmed, "base64"),
        format: "der",
        type: "pkcs8",
      });
  return createPublicKey(priv).export({ type: "spki", format: "der" }) as Buffer;
}

function isExampleSigningKey(privateKeyMaterial: string): boolean {
  try {
    const configured = publicKeyDerFromPrivatePemOrB64(privateKeyMaterial);
    const example = publicKeyDerFromPrivatePemOrB64(EXAMPLE_ED25519_PKCS8_B64);
    return (
      configured.length === example.length && configured.equals(example)
    );
  } catch {
    return false;
  }
}

const envSchema = z.object({
  ED25519_PRIVATE_KEY: z.string().min(32, "ED25519_PRIVATE_KEY is required"),
  ED25519_KEY_ID: z.string().min(1).default("local-dev"),
  SIGNING_PROVIDER: z.string().default("local"),
  WATERMARK_KEY: z.string().min(8).default("dev-watermark-key-change-me"),
  MAX_UPLOAD_MB: z.coerce.number().positive().default(25),
  STORAGE_DIR: z.string().default("./storage"),
  /** local | blob | auto (blob when BLOB_READ_WRITE_TOKEN is set) */
  STORAGE_PROVIDER: z.enum(["local", "blob", "auto"]).default("auto"),
  DATABASE_URL: z.string().min(1),
  TSA_URL: z.string().url().default("https://freetsa.org/tsr"),
  CHECKPOINT_EVERY_N_ENTRIES: z.coerce.number().int().positive().default(10),
  CRON_SECRET: z.string().optional(),
  REDIS_URL: z.string().optional(),
  /** Watermark confidence required to trust extracted certId */
  WATERMARK_CONFIDENCE_MIN: z.coerce.number().min(0).max(1).default(0.7),
  /** Max Hamming distance for perceptual hash matching */
  PHASH_MATCH_MAX: z.coerce.number().int().positive().default(12),
  /** Tamper score alert threshold; below → MODIFIED_REENCODED */
  TAMPER_SCORE_ALERT: z.coerce.number().positive().default(1.5),
  /** Cell dHash Hamming threshold (of 64) */
  CELL_HAMMING_THRESHOLD: z.coerce.number().int().positive().default(12),
  /** Cell mean-luminance delta threshold (0–255) */
  CELL_LUMA_DELTA_THRESHOLD: z.coerce.number().positive().default(18),
  /**
   * Single-cell Hamming above this → localized TAMPERED.
   * Default 48: brightness clamp / resize noise routinely hits ham 24–40.
   * Zod is the SSOT — loadConfig must not ??-override this.
   */
  CELL_STRONG_HAMMING: z.coerce.number().int().positive().default(48),
  /** Single-cell luma delta above this → localized TAMPERED */
  CELL_STRONG_LUMA: z.coerce.number().positive().default(40),
  /** Connected outlier-cell cluster size that counts as tamper */
  TAMPER_MIN_CLUSTER_CELLS: z.coerce.number().int().positive().default(2),
  /** % of grid changed above this + few outliers → GLOBAL_ADJUSTMENT */
  GLOBAL_CHANGE_MIN_PERCENT: z.coerce.number().positive().default(60),
  /**
   * Outlier multiplier on MAD (robust z-score). K=6 keeps JPEG q70 noise
   * under the floor while 64px+ block edits still form outlier clusters.
   */
  OUTLIER_K: z.coerce.number().positive().default(6),
  /** Absolute minimum cell deviation to count as an outlier */
  OUTLIER_ABS_FLOOR: z.coerce.number().positive().default(0.15),
  /**
   * Min connected pixel-diff region area at 1024×1024 reference; scales with
   * image area. 80px catches ~24–32px digit erasures after blur/threshold.
   */
  PIXEL_MIN_REGION_AREA: z.coerce.number().int().positive().default(80),
  /** Default grid size for cell signatures */
  IMAGE_GRID_SIZE: z.coerce.number().int().positive().default(32),
  /** QIM quantization step for watermark embedding */
  WATERMARK_QIM_STEP: z.coerce.number().positive().default(24),
});

/**
 * Pass raw process.env values (undefined when unset) so zod `.default()` is
 * the single source of truth. Never `?? literal` for tunables — that silently
 * overrides the schema default (e.g. CELL_STRONG_HAMMING 20 vs 48).
 */
function loadConfig() {
  const parsed = envSchema.safeParse({
    ED25519_PRIVATE_KEY: process.env.ED25519_PRIVATE_KEY,
    ED25519_KEY_ID: process.env.ED25519_KEY_ID,
    SIGNING_PROVIDER: process.env.SIGNING_PROVIDER,
    WATERMARK_KEY: process.env.WATERMARK_KEY,
    MAX_UPLOAD_MB: process.env.MAX_UPLOAD_MB,
    STORAGE_DIR: process.env.STORAGE_DIR,
    STORAGE_PROVIDER: process.env.STORAGE_PROVIDER,
    DATABASE_URL: process.env.DATABASE_URL,
    TSA_URL: process.env.TSA_URL,
    CHECKPOINT_EVERY_N_ENTRIES: process.env.CHECKPOINT_EVERY_N_ENTRIES,
    CRON_SECRET: process.env.CRON_SECRET,
    REDIS_URL: process.env.REDIS_URL,
    WATERMARK_CONFIDENCE_MIN: process.env.WATERMARK_CONFIDENCE_MIN,
    PHASH_MATCH_MAX: process.env.PHASH_MATCH_MAX,
    TAMPER_SCORE_ALERT: process.env.TAMPER_SCORE_ALERT,
    CELL_HAMMING_THRESHOLD: process.env.CELL_HAMMING_THRESHOLD,
    CELL_LUMA_DELTA_THRESHOLD: process.env.CELL_LUMA_DELTA_THRESHOLD,
    CELL_STRONG_HAMMING: process.env.CELL_STRONG_HAMMING,
    CELL_STRONG_LUMA: process.env.CELL_STRONG_LUMA,
    TAMPER_MIN_CLUSTER_CELLS: process.env.TAMPER_MIN_CLUSTER_CELLS,
    GLOBAL_CHANGE_MIN_PERCENT: process.env.GLOBAL_CHANGE_MIN_PERCENT,
    OUTLIER_K: process.env.OUTLIER_K,
    OUTLIER_ABS_FLOOR: process.env.OUTLIER_ABS_FLOOR,
    PIXEL_MIN_REGION_AREA: process.env.PIXEL_MIN_REGION_AREA,
    IMAGE_GRID_SIZE: process.env.IMAGE_GRID_SIZE,
    WATERMARK_QIM_STEP: process.env.WATERMARK_QIM_STEP,
  });

  if (!parsed.success) {
    const message = parsed.error.issues.map((i) => i.message).join("; ");
    throw new Error(`Invalid environment configuration: ${message}`);
  }

  return {
    ed25519PrivateKey: parsed.data.ED25519_PRIVATE_KEY,
    ed25519KeyId: parsed.data.ED25519_KEY_ID,
    signingProvider: parsed.data.SIGNING_PROVIDER,
    watermarkKey: parsed.data.WATERMARK_KEY,
    maxUploadBytes: parsed.data.MAX_UPLOAD_MB * 1024 * 1024,
    storageDir: parsed.data.STORAGE_DIR,
    storageProvider: parsed.data.STORAGE_PROVIDER,
    databaseUrl: parsed.data.DATABASE_URL,
    tsaUrl: parsed.data.TSA_URL,
    checkpointEveryNEntries: parsed.data.CHECKPOINT_EVERY_N_ENTRIES,
    cronSecret: parsed.data.CRON_SECRET,
    redisUrl: parsed.data.REDIS_URL,
    watermarkConfidenceMin: parsed.data.WATERMARK_CONFIDENCE_MIN,
    phashMatchMax: parsed.data.PHASH_MATCH_MAX,
    tamperScoreAlert: parsed.data.TAMPER_SCORE_ALERT,
    cellHammingThreshold: parsed.data.CELL_HAMMING_THRESHOLD,
    cellLumaDeltaThreshold: parsed.data.CELL_LUMA_DELTA_THRESHOLD,
    cellStrongHamming: parsed.data.CELL_STRONG_HAMMING,
    cellStrongLuma: parsed.data.CELL_STRONG_LUMA,
    tamperMinClusterCells: parsed.data.TAMPER_MIN_CLUSTER_CELLS,
    globalChangeMinPercent: parsed.data.GLOBAL_CHANGE_MIN_PERCENT,
    outlierK: parsed.data.OUTLIER_K,
    outlierAbsFloor: parsed.data.OUTLIER_ABS_FLOOR,
    pixelMinRegionArea: parsed.data.PIXEL_MIN_REGION_AREA,
    imageGridSize: parsed.data.IMAGE_GRID_SIZE,
    watermarkQimStep: parsed.data.WATERMARK_QIM_STEP,
  };
}

export type AppConfig = ReturnType<typeof loadConfig>;

let cached: AppConfig | null = null;

export function getConfig(): AppConfig {
  if (!cached) {
    cached = loadConfig();
    if (isExampleSigningKey(cached.ed25519PrivateKey)) {
      const msg =
        "ED25519_PRIVATE_KEY matches the old public example key — generate a unique key before deploying.";
      if (process.env.NODE_ENV === "production") {
        throw new Error(msg);
      }
      console.warn(`\n⚠️  WARNING: ${msg}\n`);
    }
  }
  return cached;
}

/** Reset cached config (for tests). */
export function resetConfigCache(): void {
  cached = null;
}

export const CHUNK_SIZE = 4096; // 4 KB
export const PLATFORM_NAME = "doc-detective";
export const WATERMARK_VERSION = 1;
