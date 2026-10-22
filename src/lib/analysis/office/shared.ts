import JSZip from "jszip";
import { createHash } from "crypto";

export async function unzip(buf: Buffer): Promise<JSZip> {
  return JSZip.loadAsync(buf);
}

export async function readText(
  zip: JSZip,
  path: string,
): Promise<string | null> {
  const f = zip.file(path);
  if (!f) return null;
  return f.async("string");
}

export async function fileSha256(
  zip: JSZip,
  path: string,
): Promise<string | null> {
  const f = zip.file(path);
  if (!f) return null;
  const data = await f.async("nodebuffer");
  return createHash("sha256").update(data).digest("hex");
}

export function stripXmlTags(xml: string): string {
  return xml
    .replace(/<w:tab\/>/g, "\t")
    .replace(/<w:br\/>/g, "\n")
    .replace(/<\/w:p>/g, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export async function compareCoreProps(
  a: JSZip,
  b: JSZip,
): Promise<string[]> {
  const diffs: string[] = [];
  const path = "docProps/core.xml";
  const ta = await readText(a, path);
  const tb = await readText(b, path);
  if ((ta ?? "") !== (tb ?? "")) {
    diffs.push("docProps/core.xml metadata differs");
  }
  const appA = await readText(a, "docProps/app.xml");
  const appB = await readText(b, "docProps/app.xml");
  if ((appA ?? "") !== (appB ?? "")) {
    diffs.push("docProps/app.xml differs");
  }
  return diffs;
}
