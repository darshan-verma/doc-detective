import { timingSafeEqual } from "crypto";
import { AppError, errorResponse } from "@/lib/errors";
import { verifyAndRecordLogChain } from "@/lib/trust/log";
import { runCheckpointJob } from "@/lib/trust/timestamp/checkpoint";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function bearerMatches(expected: string, authHeader: string): boolean {
  if (!authHeader.startsWith("Bearer ")) return false;
  const token = authHeader.slice("Bearer ".length);
  const a = Buffer.from(token, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Cron-triggered checkpoint job. Protect with CRON_SECRET:
 * Authorization: Bearer <CRON_SECRET>
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
    if (!bearerMatches(expected, auth)) {
      throw new AppError("BAD_REQUEST", "Unauthorized", 401);
    }

    const url = new URL(request.url);
    const force = url.searchParams.get("force") === "1";
    const chain = await verifyAndRecordLogChain();
    const result = await runCheckpointJob({ force });
    return Response.json({ ...result, chain });
  } catch (err) {
    return errorResponse(err);
  }
}

export async function GET(request: Request) {
  return POST(request);
}
