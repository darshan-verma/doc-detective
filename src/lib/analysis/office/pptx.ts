import {
  Verdict,
  type AnalysisChange,
  type AnalysisResult,
  type Analyzer,
  type CheckResult,
} from "../types";
import { sha256Buffer } from "../verdict";
import {
  compareCoreProps,
  fileSha256,
  readText,
  stripXmlTags,
  unzip,
} from "./shared";

export class PptxAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return (
      ext === ".pptx" ||
      mime ===
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
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

    const checks: CheckResult[] = [];
    const changes: AnalysisChange[] = [];
    const [za, zb] = await Promise.all([unzip(original), unzip(uploaded)]);

    const metaDiffs = await compareCoreProps(za, zb);
    checks.push({
      name: "metadata",
      status: metaDiffs.length ? "FAILED" : "PASSED",
    });

    const slidesA = Object.keys(za.files)
      .filter((p) => /^ppt\/slides\/slide\d+\.xml$/.test(p))
      .sort();
    const slidesB = Object.keys(zb.files)
      .filter((p) => /^ppt\/slides\/slide\d+\.xml$/.test(p))
      .sort();

    let contentFailed = false;
    if (slidesA.length !== slidesB.length) {
      contentFailed = true;
      changes.push({
        description: `Slide count ${slidesA.length} → ${slidesB.length}`,
        kind: "slides",
      });
    }

    for (const slide of new Set([...slidesA, ...slidesB])) {
      const ta = stripXmlTags((await readText(za, slide)) ?? "");
      const tb = stripXmlTags((await readText(zb, slide)) ?? "");
      if (ta !== tb) {
        contentFailed = true;
        changes.push({
          location: slide,
          description: "Slide text differs",
          kind: "text",
        });
      }
    }

    // Speaker notes
    const notesA = Object.keys(za.files).filter((p) =>
      p.startsWith("ppt/notesSlides/"),
    );
    const notesB = Object.keys(zb.files).filter((p) =>
      p.startsWith("ppt/notesSlides/"),
    );
    for (const n of new Set([...notesA, ...notesB])) {
      const ta = stripXmlTags((await readText(za, n)) ?? "");
      const tb = stripXmlTags((await readText(zb, n)) ?? "");
      if (ta !== tb) {
        contentFailed = true;
        changes.push({
          location: n,
          description: "Speaker notes differ",
          kind: "notes",
        });
      }
    }

    // Media hashes
    for (const m of new Set([
      ...Object.keys(za.files).filter((p) => p.startsWith("ppt/media/")),
      ...Object.keys(zb.files).filter((p) => p.startsWith("ppt/media/")),
    ])) {
      if ((await fileSha256(za, m)) !== (await fileSha256(zb, m))) {
        contentFailed = true;
        changes.push({
          location: m,
          description: "Embedded media differs",
          kind: "media",
        });
      }
    }

    checks.push({
      name: "slides",
      status: contentFailed ? "FAILED" : "PASSED",
    });

    if (contentFailed) {
      return {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks,
        changes,
        notChecked: [],
      };
    }
    if (metaDiffs.length) {
      return {
        verdict: Verdict.MODIFIED_FORMAT_ONLY,
        confidence: "HIGH",
        checks,
        changes: metaDiffs.map((d) => ({ description: d, kind: "metadata" })),
        notChecked: [],
      };
    }
    return {
      verdict: Verdict.MODIFIED_FORMAT_ONLY,
      confidence: "MEDIUM",
      checks,
      changes: [{ description: "Package bytes differ; slide content matches" }],
      notChecked: [],
    };
  }
}
