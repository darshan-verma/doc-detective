import { createHash } from "crypto";
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import type { AnalysisResult } from "./analysis/types";
import { explainAnalysis } from "./explain";
import { replaceUnencodable, sanitizeForDisplay } from "./sanitize";

export interface ReportInput {
  certId: string;
  verdict: string;
  analysis?: AnalysisResult | null;
  signatureValid?: boolean;
  timestampStatus?: string;
  tsaGenTime?: string | null;
  registeredSha256: string;
  uploadedSha256: string;
  verifiedAt?: Date;
  revoked?: boolean;
  /** Test-only: force named sections to throw. */
  _testFailSections?: string[];
}

function makeSafeDrawer(
  font: PDFFont,
  bold: PDFFont,
): {
  draw: (
    page: PDFPage,
    text: string,
    opts: { x: number; y: number; size: number; useBold?: boolean },
  ) => void;
} {
  // Helvetica uses WinAnsiEncoding — allow printable ASCII + common Latin-1.
  void font;
  const canEncode = (cp: number) =>
    (cp >= 0x20 && cp <= 0x7e) || (cp >= 0xa0 && cp <= 0xff);
  return {
    draw(page, text, opts) {
      const cleaned = replaceUnencodable(
        sanitizeForDisplay(text),
        canEncode,
      );
      if (!cleaned) return;
      page.drawText(cleaned.slice(0, 120), {
        x: opts.x,
        y: opts.y,
        size: opts.size,
        font: opts.useBold ? bold : font,
        color: rgb(0.1, 0.1, 0.1),
      });
    },
  };
}

/** Run a report section; on failure append a placeholder and continue. */
export async function runReportSection(
  name: string,
  fn: () => void | Promise<void>,
  onFail: (message: string) => void,
  testFail?: string[],
): Promise<void> {
  try {
    if (testFail?.includes(name)) {
      throw new Error(`Forced test failure in section ${name}`);
    }
    await fn();
  } catch (err) {
    console.error(`[report] section "${name}" failed:`, err);
    onFail("This section could not be generated");
  }
}

/**
 * Build a verification report PDF from the stored analysis result only.
 * Does not require the uploaded file bytes.
 */
export async function buildVerificationReportPdf(
  input: ReportInput,
): Promise<{ pdf: Buffer; sha256: string }> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const { draw } = makeSafeDrawer(font, bold);

  let page = doc.addPage([612, 792]);
  let y = 760;
  const left = 48;
  const bottom = 48;

  const ensureSpace = (need = 24) => {
    if (y < bottom + need) {
      page = doc.addPage([612, 792]);
      y = 760;
    }
  };

  const line = (text: string, size = 11, useBold = false) => {
    ensureSpace(size + 8);
    draw(page, text, { x: left, y, size, useBold });
    y -= size + 6;
  };

  const plain = input.analysis
    ? explainAnalysis(input.analysis, { revoked: input.revoked })
    : null;

  await runReportSection(
    "summary",
    () => {
      line("doc-detective verification report", 16, true);
      line(`Certificate: ${input.certId}`, 12, true);
      line(`Verdict: ${input.revoked ? "REVOKED" : input.verdict}`, 12, true);
      if (plain) {
        line(plain.headline, 11, true);
        for (const sentence of wrap(plain.explanation, 90)) line(sentence, 10);
        line(
          `Confidence: ${plain.confidenceBadge.label} - ${plain.confidenceBadge.reason}`,
          10,
        );
      }
    },
    (msg) => line(msg, 10),
    input._testFailSections,
  );

  y -= 4;
  await runReportSection(
    "checks",
    () => {
      line("What we checked", 11, true);
      if (plain) {
        for (const c of plain.whatWeChecked) {
          const detail = c.detail ? `: ${sanitizeForDisplay(c.detail)}` : "";
          line(`- [${c.status}] ${c.name}${detail}`, 9);
        }
        if (plain.whatWeCouldNotCheck.length) {
          line("What we could not check", 11, true);
          for (const n of plain.whatWeCouldNotCheck) line(`- ${n}`, 9);
        }
      }
      const formatDiffs = input.analysis?.formatDifferences ?? [];
      if (formatDiffs.length > 0) {
        line("File was also re-saved by a different program", 11, true);
        for (const d of formatDiffs.slice(0, 20)) {
          line(`- ${sanitizeForDisplay(d.description)}`, 9);
        }
      }
    },
    (msg) => line(msg, 10),
    input._testFailSections,
  );

  y -= 4;
  await runReportSection(
    "diffs",
    () => {
      const changes = input.analysis?.changes ?? [];
      if (changes.length === 0) return;
      line("Content changes", 11, true);
      for (const c of changes.slice(0, 40)) {
        const loc = c.location ? `${c.location}: ` : "";
        line(`- ${loc}${sanitizeForDisplay(c.description)}`, 9);
      }
    },
    (msg) => line(msg, 10),
    input._testFailSections,
  );

  y -= 4;
  await runReportSection(
    "images",
    () => {
      const pages = input.analysis?.visualPages ?? [];
      if (pages.length === 0) return;
      line("Visual differences", 11, true);
      for (const vp of pages) {
        if (vp.changedPercent <= 0) continue;
        line(
          `Page ${vp.page}: ${vp.changedPercent.toFixed(2)}% changed, ${vp.boxes.length} region(s)`,
          9,
        );
      }
    },
    (msg) => line(msg, 10),
    input._testFailSections,
  );

  y -= 4;
  await runReportSection(
    "certificate",
    () => {
      line(
        `Signature valid: ${input.signatureValid == null ? "n/a" : String(input.signatureValid)}`,
        10,
      );
      line(`Timestamp status: ${input.timestampStatus ?? "n/a"}`, 10);
      if (input.tsaGenTime) line(`TSA genTime: ${input.tsaGenTime}`, 10);
      line(`Registered SHA-256: ${input.registeredSha256}`, 8);
      line(`Uploaded SHA-256:   ${input.uploadedSha256}`, 8);
      line(
        `Verified at: ${(input.verifiedAt ?? new Date()).toISOString()}`,
        10,
      );
      y -= 8;
      if (plain) {
        for (const sentence of wrap(plain.disclaimer, 90)) line(sentence, 8);
      }
    },
    (msg) => line(msg, 10),
    input._testFailSections,
  );

  const pdf = Buffer.from(await doc.save());
  const sha256 = createHash("sha256").update(pdf).digest("hex");
  return { pdf, sha256 };
}

function wrap(text: string, width: number): string[] {
  const words = sanitizeForDisplay(text).split(/\s+/);
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > width) {
      if (cur) lines.push(cur);
      cur = w;
    } else {
      cur = (cur + " " + w).trim();
    }
  }
  if (cur) lines.push(cur);
  return lines;
}
