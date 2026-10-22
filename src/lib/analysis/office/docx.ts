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

export class DocxAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return (
      ext === ".docx" ||
      mime ===
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
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
    const notChecked: string[] = [];

    const [za, zb] = await Promise.all([unzip(original), unzip(uploaded)]);

    const metaDiffs = await compareCoreProps(za, zb);
    checks.push({
      name: "metadata",
      status: metaDiffs.length ? "FAILED" : "PASSED",
      detail: metaDiffs.join("; ") || "Metadata identical",
    });
    for (const d of metaDiffs) {
      changes.push({ description: d, kind: "metadata", location: "docProps" });
    }

    const docA = (await readText(za, "word/document.xml")) ?? "";
    const docB = (await readText(zb, "word/document.xml")) ?? "";
    const textA = stripXmlTags(docA);
    const textB = stripXmlTags(docB);
    const textDiff = textA !== textB;
    checks.push({
      name: "paragraph-text",
      status: textDiff ? "FAILED" : "PASSED",
      detail: textDiff ? "Body text differs" : "Body text identical",
    });
    if (textDiff) {
      changes.push({
        location: "word/document.xml",
        description: "Paragraph/run text differs",
        kind: "text",
      });
    }

    // Tracked changes / comments / headers
    for (const part of [
      "word/comments.xml",
      "word/header1.xml",
      "word/footer1.xml",
    ]) {
      const ha = await fileSha256(za, part);
      const hb = await fileSha256(zb, part);
      if (ha !== hb && (ha || hb)) {
        changes.push({
          location: part,
          description: `${part} differs`,
          kind: "structure",
        });
      }
    }

    const hasTracked =
      docA.includes("w:ins") ||
      docA.includes("w:del") ||
      docB.includes("w:ins") ||
      docB.includes("w:del");
    if (hasTracked && docA !== docB) {
      changes.push({
        description: "Tracked changes markup differs",
        kind: "tracked-changes",
      });
    }

    // Embedded media
    const mediaA = Object.keys(za.files).filter((p) =>
      p.startsWith("word/media/"),
    );
    const mediaB = Object.keys(zb.files).filter((p) =>
      p.startsWith("word/media/"),
    );
    for (const m of new Set([...mediaA, ...mediaB])) {
      const ha = await fileSha256(za, m);
      const hb = await fileSha256(zb, m);
      if (ha !== hb) {
        changes.push({
          location: m,
          description: `Embedded media hash differs`,
          kind: "media",
        });
        checks.push({
          name: "embedded-media",
          status: "FAILED",
          detail: m,
        });
      }
    }
    if (!checks.some((c) => c.name === "embedded-media")) {
      checks.push({ name: "embedded-media", status: "PASSED" });
    }

    const contentFailed = checks.some(
      (c) =>
        (c.name === "paragraph-text" || c.name === "embedded-media") &&
        c.status === "FAILED",
    );
    const formatFailed = checks.some(
      (c) => c.name === "metadata" && c.status === "FAILED",
    );

    if (contentFailed) {
      return {
        verdict: Verdict.TAMPERED,
        confidence: "HIGH",
        checks,
        changes,
        notChecked,
      };
    }
    if (formatFailed) {
      return {
        verdict: Verdict.MODIFIED_FORMAT_ONLY,
        confidence: "HIGH",
        checks,
        changes: changes.filter((c) => c.kind === "metadata"),
        notChecked,
      };
    }

    // Bytes differ but structured content same
    return {
      verdict: Verdict.MODIFIED_FORMAT_ONLY,
      confidence: "MEDIUM",
      checks,
      changes: [
        { description: "Package bytes differ without detected content change" },
      ],
      notChecked,
    };
  }
}
