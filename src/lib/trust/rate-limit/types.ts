export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export interface RateLimiter {
  /**
   * Consume one request for `key` within `windowMs`.
   * `limit` is the max allowed in that window.
   */
  check(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<RateLimitResult>;
}
