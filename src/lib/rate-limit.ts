/** @deprecated Import from `@/lib/trust/rate-limit` — kept for route compatibility. */
export {
  rateLimit,
  resetRateLimits,
  clientKey,
  getRateLimiter,
  setRateLimiter,
  MemoryRateLimiter,
  RedisRateLimiter,
} from "./trust/rate-limit";
export type { RateLimiter, RateLimitResult } from "./trust/rate-limit";
