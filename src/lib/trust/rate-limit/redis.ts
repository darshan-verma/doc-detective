import type { RateLimiter, RateLimitResult } from "./types";
import { MemoryRateLimiter } from "./memory";

type RedisLike = {
  incr: (key: string) => Promise<number>;
  pExpire: (key: string, ms: number) => Promise<unknown>;
  pTtl: (key: string) => Promise<number>;
};

/**
 * Redis-backed fixed-window limiter. Falls back to in-memory if the Redis
 * connection cannot be established (so local/dev never hard-fails).
 */
export class RedisRateLimiter implements RateLimiter {
  private client: RedisLike | null = null;
  private fallback = new MemoryRateLimiter();
  private initPromise: Promise<void> | null = null;
  private readonly url: string;

  constructor(url: string) {
    this.url = url;
  }

  private async ensureClient(): Promise<void> {
    if (this.client) return;
    if (!this.initPromise) {
      this.initPromise = this.connect();
    }
    await this.initPromise;
  }

  private async connect(): Promise<void> {
    try {
      const redis = await import("redis");
      const c = redis.createClient({ url: this.url });
      c.on("error", () => {
        /* swallow — fallback handles traffic */
      });
      await c.connect();
      this.client = c;
    } catch {
      this.client = null;
    }
  }

  async check(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<RateLimitResult> {
    await this.ensureClient();
    if (!this.client) {
      return this.fallback.check(key, limit, windowMs);
    }

    const redisKey = `rl:${key}`;
    try {
      const count = await this.client.incr(redisKey);
      if (count === 1) {
        await this.client.pExpire(redisKey, windowMs);
      }
      const ttl = await this.client.pTtl(redisKey);
      const resetAt = Date.now() + (ttl > 0 ? ttl : windowMs);
      if (count > limit) {
        return { allowed: false, remaining: 0, resetAt };
      }
      return { allowed: true, remaining: Math.max(0, limit - count), resetAt };
    } catch {
      return this.fallback.check(key, limit, windowMs);
    }
  }
}
