import { listPublishedKeys } from "@/lib/trust/keys";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Publish all signing public keys (active + rotated). Never deletes keys. */
export async function GET() {
  const keys = await listPublishedKeys();
  return Response.json(
    {
      keys,
      algorithm: "See per-key alg field",
      note: "Private keys are never published. Rotated keys remain verifiable forever.",
    },
    {
      headers: {
        "Cache-Control": "public, max-age=60",
      },
    },
  );
}
