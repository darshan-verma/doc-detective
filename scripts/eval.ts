/**
 * Eval harness: analyze each corpus variant and print a confusion matrix.
 * Exit non-zero if false negatives > 0 or false-positive rate above cap.
 *
 * False positive = genuine (AUTHENTIC / format-only expected) flagged TAMPERED
 * False negative = forged (TAMPERED expected) marked AUTHENTIC/MODIFIED_FORMAT_ONLY
 */
import { readFile } from "fs/promises";
import path from "path";
import { analyzePair, Verdict, analysisConfig } from "../src/lib/analysis";

interface Case {
  id: string;
  file: string;
  variant: string;
  expectedVerdict: string;
}

interface Manifest {
  falsePositiveRateMax?: number;
  cases: Case[];
}

async function main() {
  const corpusDir = path.join(process.cwd(), "tests/corpus");
  const manifest = JSON.parse(
    await readFile(path.join(corpusDir, "manifest.json"), "utf8"),
  ) as Manifest;

  const fpCap =
    manifest.falsePositiveRateMax ?? analysisConfig.evalFalsePositiveRateMax;

  let fp = 0;
  let fn = 0;
  let tp = 0;
  let tn = 0;
  const rows: string[] = [];

  for (const c of manifest.cases) {
    const original = await readFile(path.join(corpusDir, c.file));
    const uploaded = await readFile(path.join(corpusDir, c.variant));
    const name = path.basename(c.file);
    const result = await analyzePair({
      original,
      uploaded,
      originalName: name,
      mimeType: mimeFromName(name),
    });

    const expected = c.expectedVerdict;
    const got = result.verdict;
    const ok = got === expected;
    rows.push(
      `${ok ? "OK" : "MISS"}\t${c.id}\texpected=${expected}\tgot=${got}`,
    );

    const expectedForged = expected === Verdict.TAMPERED;
    const gotForged = got === Verdict.TAMPERED;
    const expectedClean =
      expected === Verdict.AUTHENTIC ||
      expected === Verdict.MODIFIED_FORMAT_ONLY;
    const gotClean =
      got === Verdict.AUTHENTIC || got === Verdict.MODIFIED_FORMAT_ONLY;

    if (expectedForged && gotForged) tp++;
    else if (expectedClean && gotClean) tn++;
    else if (expectedClean && gotForged) fp++;
    else if (expectedForged && gotClean) fn++;
    else if (expectedForged && got === Verdict.ANALYSIS_UNAVAILABLE) fn++;
    // other mismatches count toward neither strictly; treat unexpected as miss
    else if (!ok && expectedForged) fn++;
    else if (!ok && expectedClean) fp++;
  }

  console.log(rows.join("\n"));
  console.log("\nConfusion (forged=TAMPERED vs clean=AUTHENTIC|MODIFIED_FORMAT_ONLY):");
  console.log(`  TP=${tp} TN=${tn} FP=${fp} FN=${fn}`);

  const cleanTotal = tn + fp;
  const fpRate = cleanTotal === 0 ? 0 : fp / cleanTotal;
  console.log(`  false-positive rate=${fpRate.toFixed(3)} (cap ${fpCap})`);
  console.log(`  false-negatives=${fn} (cap 0)`);

  if (fn > 0 || fpRate > fpCap) {
    process.exit(1);
  }
  process.exit(0);
}

function mimeFromName(name: string): string {
  const ext = path.extname(name).toLowerCase();
  const map: Record<string, string> = {
    ".txt": "text/plain",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".pdf": "application/pdf",
    ".docx":
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx":
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx":
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  };
  return map[ext] ?? "application/octet-stream";
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
