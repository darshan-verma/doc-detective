/**
 * Strip private-use and control characters from text for UI and PDF report display.
 * Keeps newlines and tabs; removes U+E000–U+F8FF (e.g. Wingdings U+F0B7) and C0/C1 controls.
 * Unicode punctuation (arrows, dashes, curly quotes, ellipsis) is preserved — the PDF
 * report embeds Noto Sans.
 */
export function sanitizeForDisplay(text: string): string {
  if (!text) return text;
  return (
    text
      .replace(/\u00A0/g, " ")
      .replace(
        // eslint-disable-next-line no-control-regex
        /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\uE000-\uF8FF]/g,
        "",
      )
  );
}

/** Replace characters a PDF font cannot encode with "?". */
export function replaceUnencodable(
  text: string,
  canEncode: (codePoint: number) => boolean,
): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    out += canEncode(cp) ? ch : "?";
  }
  return out;
}
