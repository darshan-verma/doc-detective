import { z } from "zod";

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
   * Default 48 (not 20): uniform brightness clamping and 50% down/up resize
   * routinely produce per-cell ham 24–40 on textured pages; those must reach
   * GLOBAL_ADJUSTMENT. Localized block edits still trip cluster size ≥ 2.
   */
  CELL_STRONG_HAMMING: z.coerce.number().int().positive().default(48),
  /** Single-cell luma delta above this → localized TAMPERED */
  CELL_STRONG_LUMA: z.coerce.number().positive().default(40),
  /** Connected changed-cell cluster size that counts as tamper */
  TAMPER_MIN_CLUSTER_CELLS: z.coerce.number().int().positive().default(2),
  /** % of grid changed above this + consistent luma → GLOBAL_ADJUSTMENT */
  GLOBAL_CHANGE_MIN_PERCENT: z.coerce.number().positive().default(60),
  /** Default grid size for cell signatures */
  IMAGE_GRID_SIZE: z.coerce.number().int().positive().default(32),
  /** QIM quantization step for watermark embedding */
  WATERMARK_QIM_STEP: z.coerce.number().positive().default(24),
});

function loadConfig() {
  const parsed = envSchema.safeParse({
    ED25519_PRIVATE_KEY: process.env.ED25519_PRIVATE_KEY,
    ED25519_KEY_ID: process.env.ED25519_KEY_ID ?? "local-dev",
    SIGNING_PROVIDER: process.env.SIGNING_PROVIDER ?? "local",
    WATERMARK_KEY: process.env.WATERMARK_KEY ?? "dev-watermark-key-change-me",
    MAX_UPLOAD_MB: process.env.MAX_UPLOAD_MB ?? 25,
    STORAGE_DIR: process.env.STORAGE_DIR ?? "./storage",
    STORAGE_PROVIDER: process.env.STORAGE_PROVIDER ?? "auto",
    DATABASE_URL: process.env.DATABASE_URL,
    TSA_URL: process.env.TSA_URL ?? "https://freetsa.org/tsr",
    CHECKPOINT_EVERY_N_ENTRIES: process.env.CHECKPOINT_EVERY_N_ENTRIES ?? 10,
    CRON_SECRET: process.env.CRON_SECRET,
    REDIS_URL: process.env.REDIS_URL,
    WATERMARK_CONFIDENCE_MIN: process.env.WATERMARK_CONFIDENCE_MIN ?? 0.7,
    PHASH_MATCH_MAX: process.env.PHASH_MATCH_MAX ?? 12,
    TAMPER_SCORE_ALERT: process.env.TAMPER_SCORE_ALERT ?? 1.5,
    CELL_HAMMING_THRESHOLD: process.env.CELL_HAMMING_THRESHOLD ?? 12,
    CELL_LUMA_DELTA_THRESHOLD: process.env.CELL_LUMA_DELTA_THRESHOLD ?? 18,
    CELL_STRONG_HAMMING: process.env.CELL_STRONG_HAMMING ?? 20,
    CELL_STRONG_LUMA: process.env.CELL_STRONG_LUMA ?? 40,
    TAMPER_MIN_CLUSTER_CELLS: process.env.TAMPER_MIN_CLUSTER_CELLS ?? 2,
    GLOBAL_CHANGE_MIN_PERCENT: process.env.GLOBAL_CHANGE_MIN_PERCENT ?? 60,
    IMAGE_GRID_SIZE: process.env.IMAGE_GRID_SIZE ?? 32,
    WATERMARK_QIM_STEP: process.env.WATERMARK_QIM_STEP ?? 24,
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
    imageGridSize: parsed.data.IMAGE_GRID_SIZE,
    watermarkQimStep: parsed.data.WATERMARK_QIM_STEP,
  };
}

export type AppConfig = ReturnType<typeof loadConfig>;

let cached: AppConfig | null = null;

export function getConfig(): AppConfig {
  if (!cached) {
    cached = loadConfig();
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
