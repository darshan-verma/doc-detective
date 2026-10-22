import { certifyUpload } from "@/lib/certificates/service";
import { AppError, errorResponse } from "@/lib/errors";
import { clientKey, rateLimit } from "@/lib/rate-limit";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    const rl = await rateLimit(clientKey(request, "certify"), 20, 60_000);
    if (!rl.allowed) {
      throw new AppError(
        "RATE_LIMITED",
        "Too many certify requests. Try again shortly.",
        429,
      );
    }

    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      throw new AppError("BAD_REQUEST", "Missing file field", 400);
    }

    const stampRaw = form.get("addVerificationStamp");
    const addVerificationStamp =
      stampRaw === "true" || stampRaw === "1" || stampRaw === "on";
    const forceRaw = form.get("force");
    const force = forceRaw === "true" || forceRaw === "1" || forceRaw === "on";
    const parentCertId =
      typeof form.get("parentCertId") === "string"
        ? String(form.get("parentCertId")).trim() || null
        : null;
    const ownerToken =
      typeof form.get("ownerToken") === "string"
        ? String(form.get("ownerToken")).trim() || null
        : null;
    const visibilityRaw = form.get("visibility");
    const visibility =
      visibilityRaw === "PUBLIC" ? ("PUBLIC" as const) : ("LIMITED" as const);

    const origin = new URL(request.url).origin;

    const result = await certifyUpload(file, {
      addVerificationStamp,
      parentCertId,
      ownerToken,
      visibility,
      origin,
      force,
    });

    if (result.status === "ALREADY_CERTIFIED") {
      return Response.json(result, { status: 200 });
    }
    if (result.status === "ALREADY_CERTIFIED_REVOKED") {
      return Response.json(result, { status: 200 });
    }
    return Response.json(result, { status: 201 });
  } catch (err) {
    return errorResponse(err);
  }
}
