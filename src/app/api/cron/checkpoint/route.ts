import { AppError, errorResponse } from "@/lib/errors";
import { runCheckpointJob } from "@/lib/trust/timestamp/checkpoint";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Cron-triggered checkpoint job. Protect with CRON_SECRET:
 * Authorization: Bearer <CRON_SECRET>  or  ?secret=
 */
export async function POST(request: Request) {
  try {
    const expected = process.env.CRON_SECRET;
    if (!expected) {
      throw new AppError(
        "INTERNAL",
        "CRON_SECRET is not configured",
        500,
      );
    }

    const auth = request.headers.get("authorization") ?? "";
    const url = new URL(request.url);
    const querySecret = url.searchParams.get("secret") ?? "";
    const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (bearer !== expected && querySecret !== expected) {
      throw new AppError("BAD_REQUEST", "Unauthorized", 401);
    }

    const force = url.searchParams.get("force") === "1";
    const result = await runCheckpointJob({ force });
    return Response.json(result);
  } catch (err) {
    return errorResponse(err);
  }
}

export async function GET(request: Request) {
  return POST(request);
}
