import { Worker, isMainThread, parentPort, workerData } from "worker_threads";
import { analysisConfig } from "./config";
import { unavailableResult } from "./verdict";
import type { AnalysisResult, Analyzer } from "./types";
import { Verdict } from "./types";

/**
 * Run an analyzer with a wall-clock timeout.
 * On timeout/crash → ANALYSIS_UNAVAILABLE (never AUTHENTIC).
 *
 * Uses Promise.race in-process by default (simpler, no worker serialization).
 * Set ANALYZER_USE_WORKER=true to isolate in a worker thread when available.
 */
export async function runAnalyzer(
  analyzer: Analyzer,
  original: Buffer,
  uploaded: Buffer,
  timeoutMs = analysisConfig.analyzerTimeoutMs,
): Promise<AnalysisResult> {
  if (process.env.ANALYZER_USE_WORKER === "true" && isMainThread) {
    return runInWorker(analyzer.constructor.name, original, uploaded, timeoutMs);
  }

  try {
    const result = await Promise.race([
      analyzer.analyze(original, uploaded),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Analyzer timed out after ${timeoutMs}ms`)),
          timeoutMs,
        ),
      ),
    ]);

    // Safety: never promote AUTHENTIC if a needed check failed to run
    if (
      result.verdict === Verdict.AUTHENTIC &&
      result.notChecked.length > 0 &&
      result.checks.some((c) => c.status === "NOT_CHECKED")
    ) {
      return {
        ...result,
        verdict: Verdict.ANALYSIS_UNAVAILABLE,
        confidence: "LOW",
      };
    }
    return result;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return unavailableResult(msg, ["full analysis"]);
  }
}

async function runInWorker(
  analyzerName: string,
  original: Buffer,
  uploaded: Buffer,
  timeoutMs: number,
): Promise<AnalysisResult> {
  // Worker path is reserved for future isolation; fall back for now.
  void analyzerName;
  void Worker;
  void parentPort;
  void workerData;
  return unavailableResult("Worker isolation not configured", [
    "full analysis",
  ]);
}
