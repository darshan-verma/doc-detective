import {
  Verdict,
  type AnalysisChange,
  type AnalysisResult,
  type Analyzer,
  type CheckResult,
} from "../types";
import { sha256Buffer } from "../verdict";
import { compareCoreProps, readText, unzip } from "./shared";

function extractSheetCells(xml: string): Map<string, string> {
  const map = new Map<string, string>();
  const cellRe = /<c\b([^>]*)>([\s\S]*?)<\/c>/g;
  let m: RegExpExecArray | null;
  while ((m = cellRe.exec(xml))) {
    const attrs = m[1]!;
    const body = m[2]!;
    const refMatch = /\br="([A-Z]+\d+)"/.exec(attrs);
    if (!refMatch) continue;
    const ref = refMatch[1]!;
    const formula = /<f\b[^>]*>([\s\S]*?)<\/f>/.exec(body)?.[1]?.trim();
    const value = /<v\b[^>]*>([\s\S]*?)<\/v>/.exec(body)?.[1]?.trim() ?? "";
    map.set(ref, formula ? `=${formula}|${value}` : value);
  }
  return map;
}

export class XlsxAnalyzer implements Analyzer {
  supports(mime: string, ext: string): boolean {
    return (
      ext === ".xlsx" ||
      mime ===
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
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
      detail: metaDiffs.join("; ") || undefined,
    });

    const sheetsA = Object.keys(za.files)
      .filter((p) => /^xl\/worksheets\/sheet\d+\.xml$/.test(p))
      .sort();
    const sheetsB = Object.keys(zb.files)
      .filter((p) => /^xl\/worksheets\/sheet\d+\.xml$/.test(p))
      .sort();

    if (sheetsA.length !== sheetsB.length) {
      changes.push({
        description: `Sheet count ${sheetsA.length} → ${sheetsB.length}`,
        kind: "sheets",
      });
    }

    let cellFailed = false;
    for (const sheet of new Set([...sheetsA, ...sheetsB])) {
      const xa = (await readText(za, sheet)) ?? "";
      const xb = (await readText(zb, sheet)) ?? "";
      const ca = extractSheetCells(xa);
      const cb = extractSheetCells(xb);
      const refs = new Set([...ca.keys(), ...cb.keys()]);
      for (const ref of refs) {
        if ((ca.get(ref) ?? "") !== (cb.get(ref) ?? "")) {
          cellFailed = true;
          changes.push({
            location: `${sheet}:${ref}`,
            description: `Cell ${ref}: "${ca.get(ref) ?? ""}" → "${cb.get(ref) ?? ""}"`,
            kind: "cell",
          });
        }
      }
    }

    checks.push({
      name: "cells",
      status: cellFailed ? "FAILED" : "PASSED",
      detail: cellFailed ? "Cell values/formulas differ" : "Cells identical",
    });

    // Hidden sheets heuristic
    const wbA = (await readText(za, "xl/workbook.xml")) ?? "";
    const wbB = (await readText(zb, "xl/workbook.xml")) ?? "";
    if (wbA !== wbB) {
      const hiddenA = (wbA.match(/state="hidden"/g) ?? []).length;
      const hiddenB = (wbB.match(/state="hidden"/g) ?? []).length;
      if (hiddenA !== hiddenB) {
        changes.push({
          description: `Hidden sheets ${hiddenA} → ${hiddenB}`,
          kind: "hidden",
        });
        cellFailed = true;
      } else {
        checks.push({
          name: "workbook-structure",
          status: "FAILED",
          detail: "workbook.xml differs",
        });
      }
    }

    if (cellFailed) {
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
      changes: [{ description: "Package bytes differ; cell content matches" }],
      notChecked: [],
    };
  }
}
