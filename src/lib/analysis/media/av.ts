import { execFile } from "child_process";
import { mkdir, mkdtemp, writeFile, rm } from "fs/promises";
import { tmpdir } from "os";
import path from "path";
import { promisify } from "util";
import { analysisConfig } from "../config";
import {
  Verdict,
  type AnalysisResult,
  type Analyzer,
  type CheckResult,
} from "../types";
import { sha256Buffer, unavailableResult } from "../verdict";

const execFileAsync = promisify(execFile);

const AV_EXTS = new Set([
  ".mp3",
  ".wav",
  ".m4a",
  ".flac",
  ".aac",
  ".ogg",
  ".mp4",
  ".mov",
  ".webm",
  ".mkv",
  ".avi",
]);

async function which(bin: string): Promise<boolean> {
  try {
    await execFileAsync("which", [bin]);
    return true;
  } catch {
    return false;
  }
}

async function ffprobeJson(filePath: string): Promise<Record<string, unknown>> {
  const { stdout } = await execFileAsync(
    "ffprobe",
    [
      "-v",
      "quiet",
      "-print_format",
      "json",
      "-show_format",
      "-show_streams",
      filePath,
    ],
    { maxBuffer: 10 * 1024 * 1024 },
  );
  return JSON.parse(stdout) as Record<string, unknown>;
}

async function streamHash(
  filePath: string,
  map: string,
): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(
      "ffmpeg",
      ["-i", filePath, "-map", map, "-f", "hash", "-hash", "sha256", "-"],
      { maxBuffer: 2 * 1024 * 1024 },
    );
    const line = stdout.trim().split("\n").pop() ?? "";
    const hex = line.split("=").pop()?.trim();
    return hex ?? null;
  } catch {
    return null;
  }
}

export class AvAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return (
      mime.startsWith("audio/") ||
      mime.startsWith("video/") ||
      AV_EXTS.has(ext)
    );
  }

  async analyze(original: Buffer, uploaded: Buffer): Promise<AnalysisResult> {
    if (sha256Buffer(original) === sha256Buffer(uploaded)) {
      return {
        verdict: Verdict.AUTHENTIC,
        confidence: "HIGH",
        checks: [{ name: "sha256", status: "PASSED" }],
        changes: [],
        notChecked: [],
      };
    }

    if (
      original.length > analysisConfig.avMaxBytes ||
      uploaded.length > analysisConfig.avMaxBytes
    ) {
      return unavailableResult("File exceeds AV size limit", [
        "full-frame comparison",
        "stream hash",
      ]);
    }

    const hasFf = (await which("ffprobe")) && (await which("ffmpeg"));
    if (!hasFf) {
      return unavailableResult("ffprobe/ffmpeg not available", [
        "stream info",
        "stream hash",
        "full-frame comparison",
      ]);
    }

    const dir = await mkdtemp(path.join(tmpdir(), "dd-av-"));
    const origPath = path.join(dir, "original.bin");
    const upPath = path.join(dir, "uploaded.bin");
    try {
      await writeFile(origPath, original);
      await writeFile(upPath, uploaded);

      const [infoA, infoB] = await Promise.all([
        ffprobeJson(origPath),
        ffprobeJson(upPath),
      ]);

      const checks: CheckResult[] = [];
      const formatA = infoA.format as { duration?: string; tags?: unknown };
      const formatB = infoB.format as { duration?: string; tags?: unknown };
      const durA = Number(formatA.duration ?? 0);
      const durB = Number(formatB.duration ?? 0);

      if (
        durA > analysisConfig.avMaxDurationSec ||
        durB > analysisConfig.avMaxDurationSec
      ) {
        return unavailableResult("Duration exceeds AV limit", [
          "full-frame comparison",
        ]);
      }

      const metaDiff =
        JSON.stringify(formatA.tags ?? {}) !==
        JSON.stringify(formatB.tags ?? {});
      checks.push({
        name: "metadata",
        status: metaDiff ? "FAILED" : "PASSED",
      });

      const audioHashA = await streamHash(origPath, "0:a:0");
      const audioHashB = await streamHash(upPath, "0:a:0");
      const videoHashA = await streamHash(origPath, "0:v:0");
      const videoHashB = await streamHash(upPath, "0:v:0");

      const audioSame =
        audioHashA && audioHashB ? audioHashA === audioHashB : null;
      const videoSame =
        videoHashA && videoHashB ? videoHashA === videoHashB : null;

      if (audioSame !== null) {
        checks.push({
          name: "audio-stream",
          status: audioSame ? "PASSED" : "FAILED",
          detail: audioSame ? "Audio stream hash match" : "Audio stream differs",
        });
      }
      if (videoSame !== null) {
        checks.push({
          name: "video-stream",
          status: videoSame ? "PASSED" : "FAILED",
          detail: videoSame ? "Video stream hash match" : "Video stream differs",
        });
      }

      const streamsOk =
        (audioSame === null || audioSame) &&
        (videoSame === null || videoSame) &&
        (audioSame !== null || videoSame !== null);

      if (streamsOk && metaDiff) {
        return {
          verdict: Verdict.MODIFIED_FORMAT_ONLY,
          confidence: "HIGH",
          checks,
          changes: [
            {
              description:
                "Container/metadata differs; decoded streams identical",
              kind: "remux",
            },
          ],
          notChecked: ["full-frame comparison"],
        };
      }

      if (streamsOk) {
        return {
          verdict: Verdict.MODIFIED_FORMAT_ONLY,
          confidence: "MEDIUM",
          checks,
          changes: [
            { description: "Container bytes differ; streams match" },
          ],
          notChecked: ["full-frame comparison"],
        };
      }

      if (audioSame === false || videoSame === false) {
        return {
          verdict: Verdict.TAMPERED,
          confidence: "HIGH",
          checks,
          changes: [
            {
              description: "Decoded audio/video stream hash differs",
              kind: "stream",
            },
          ],
          notChecked: ["full-frame comparison"],
        };
      }

      return unavailableResult("Could not hash media streams", [
        "stream hash",
        "full-frame comparison",
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
      void mkdir;
    }
  }
}
