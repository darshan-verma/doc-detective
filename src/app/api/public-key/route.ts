import { listPublishedKeys } from "@/lib/trust/keys";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** @deprecated Prefer GET /.well-known/doc-detective/keys.json */
export async function GET() {
  const keys = await listPublishedKeys();
  const active = keys.find((k) => k.validTo == null) ?? keys[keys.length - 1];
  return Response.json({
    algorithm: active?.alg ?? "ed25519",
    keyId: active?.keyId,
    publicKey: active?.publicKey,
    keys,
  });
}
