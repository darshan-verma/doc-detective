/**
 * Normalize text for comparison so re-saved PDFs / whitespace churn
 * do not produce false-positive diffs.
 */
export function normalizeText(text: string): string {
  let s = text.normalize("NFKC");

  // All Unicode whitespace (incl. NBSP \u00A0) → single space
  s = s.replace(/\s/gu, " ");

  // Bullet / decorative list markers
  s = s.replace(
    /[\u2022\u2023\u2043\u2219\u25CF\u25E6\u00B7\u2024\u25AA\u25AB•∙‣○●]/g,
    "",
  );

  // Control / format glyphs (Cc, Cf) — after whitespace collapse
  s = s.replace(/\p{C}/gu, "");

  s = s.trim();
  s = s.replace(/ {2,}/g, " ");
  return s;
}
