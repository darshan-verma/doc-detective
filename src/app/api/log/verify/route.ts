import { errorResponse } from "@/lib/errors";
import { verifyLogChain } from "@/lib/trust/log";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Recompute the hash chain and report the first broken seq, if any. */
export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const fromRaw = url.searchParams.get("from");
    const toRaw = url.searchParams.get("to");
    const from = fromRaw != null && fromRaw !== "" ? Number(fromRaw) : undefined;
    const to = toRaw != null && toRaw !== "" ? Number(toRaw) : undefined;

    if (
      (from != null && !Number.isFinite(from)) ||
      (to != null && !Number.isFinite(to))
    ) {
      return Response.json(
        { error: { code: "BAD_REQUEST", message: "Invalid from/to" } },
        { status: 400 },
      );
    }

    const result = await verifyLogChain(from, to);
    return Response.json(result);
  } catch (err) {
    return errorResponse(err);
  }
}
