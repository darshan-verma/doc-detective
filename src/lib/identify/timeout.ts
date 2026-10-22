/** Race a promise against a timeout; on timeout returns null and does not throw. */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<{ ok: true; value: T } | { ok: false; reason: string }> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      promise.then((value) => ({ tag: "value" as const, value })),
      new Promise<{ tag: "timeout" }>((resolve) => {
        timer = setTimeout(() => resolve({ tag: "timeout" }), ms);
      }),
    ]);
    if (result.tag === "timeout") {
      return { ok: false, reason: `${label} timed out after ${ms}ms` };
    }
    return { ok: true, value: result.value };
  } catch (err) {
    return {
      ok: false,
      reason: `${label} failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Default budget for fingerprint / decode steps during identify. */
export const IDENTIFY_STEP_TIMEOUT_MS = 8_000;
