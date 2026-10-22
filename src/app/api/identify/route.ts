import { identifyFile, isStrongCandidate } from "@/lib/identify";
import { AppError, errorResponse } from "@/lib/errors";
import { clientKey, rateLimit } from "@/lib/rate-limit";

export const runtime = "nodejs";

/**
 * POST /api/identify — shared by /certify and /verify UIs.
 * Returns EXACT | LIKELY_MODIFIED_COPY | NEW with public fields only.
 */
export async function POST(request: Request) {
  try {
    const rl = await rateLimit(clientKey(request, "identify"), 40, 60_000);
    if (!rl.allowed) {
      throw new AppError(
        "RATE_LIMITED",
        "Too many identify requests. Try again shortly.",
        429,
      );
    }

    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      throw new AppError("BAD_REQUEST", "Missing file field", 400);
    }

    const result = await identifyFile(file);

    if (result.kind === "EXACT") {
      return Response.json({
        kind: "EXACT",
        matchedOn: result.matchedOn,
        certificate: result.certificate,
        revoked: Boolean(result.revokedAt),
        revokeReason: result.revokeReason,
      });
    }

    if (result.kind === "LIKELY_MODIFIED_COPY") {
      return Response.json({
        kind: "LIKELY_MODIFIED_COPY",
        candidates: result.candidates.map((c) => ({
          certId: c.certId,
          signals: c.signals,
          score: c.score,
          filenameOnly: c.filenameOnly,
          strong: isStrongCandidate(c),
          certificate: c.certificate,
        })),
        warnings: result.warnings,
      });
    }

    return Response.json({
      kind: "NEW",
      warnings: result.warnings,
    });
  } catch (err) {
    return errorResponse(err);
  }
}
