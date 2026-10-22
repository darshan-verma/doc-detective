import { describe, expect, it } from "vitest";
import {
  certifiedFilename,
  parseCertIdFromFilename,
  sanitizeFilename,
} from "../src/lib/filenames";

describe("filenames", () => {
  it("generates certified filenames", () => {
    expect(certifiedFilename("report.pdf", "K7X2M9")).toBe(
      "report_doc-detective_K7X2M9.pdf",
    );
    expect(certifiedFilename("notes", "ABC123")).toBe(
      "notes_doc-detective_ABC123",
    );
    expect(
      certifiedFilename("photo.jpg", "K7X2M9", { forceExt: ".png" }),
    ).toBe("photo_doc-detective_K7X2M9.png");
  });

  it("sanitizes path traversal and unsafe characters", () => {
    expect(sanitizeFilename("../../etc/passwd")).toBe("passwd");
    expect(sanitizeFilename("a<b>.txt")).toBe("a_b_.txt");
  });

  it("parses certId from certified filename", () => {
    expect(parseCertIdFromFilename("report_doc-detective_K7X2M9.pdf")).toBe(
      "K7X2M9",
    );
    expect(parseCertIdFromFilename("plain.pdf")).toBeNull();
  });
});
