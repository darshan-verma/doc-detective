import { MemoryRateLimiter } from "./memory";
import { RedisRateLimiter } from "./redis";
import type { RateLimiter, RateLimitResult } from "./types";

export type { RateLimiter, RateLimitResult } from "./types";
export { MemoryRateLimiter } from "./memory";
export { RedisRateLimiter } from "./redis";

let limiter: RateLimiter | null = null;
const memorySingleton = new MemoryRateLimiter();

export function getRateLimiter(): RateLimiter {
  if (!limiter) {
    const url = process.env.REDIS_URL;
    limiter = url ? new RedisRateLimiter(url) : memorySingleton;
  }
  return limiter;
}

export function setRateLimiter(next: RateLimiter | null): void {
  limiter = next;
}

/** Sync-compatible helper used by route handlers (awaits underneath). */
export async function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): Promise<RateLimitResult> {
  return getRateLimiter().check(key, limit, windowMs);
}

export function resetRateLimits(): void {
  memorySingleton.reset();
  limiter = null;
}

export function clientKey(request: Request, route: string): string {
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded?.split(",")[0]?.trim() || "local";
  return `${route}:${ip}`;
}
