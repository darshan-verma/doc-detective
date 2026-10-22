import { AppError, errorResponse } from "@/lib/errors";
import { clientKey, rateLimit } from "@/lib/rate-limit";
import { verifyUpload } from "@/lib/verify/service";

export const runtime = "nodejs";

export async function POST(request: Request) {
  try {
    const rl = await rateLimit(clientKey(request, "verify"), 30, 60_000);
    if (!rl.allowed) {
      throw new AppError(
        "RATE_LIMITED",
        "Too many verify requests. Try again shortly.",
        429,
      );
    }

    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      throw new AppError("BAD_REQUEST", "Missing file field", 400);
    }

    const certIdRaw = form.get("certId");
    const certId =
      typeof certIdRaw === "string" && certIdRaw.trim()
        ? certIdRaw.trim()
        : null;

    const result = await verifyUpload(file, certId);
    return Response.json(result);
  } catch (err) {
    return errorResponse(err);
  }
}
