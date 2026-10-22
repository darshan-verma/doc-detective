import { prisma } from "../../prisma";
import { AwsKmsProvider } from "./aws-kms";
import { LocalKeyProvider } from "./local";
import type { PublicKeyInfo, SigningProvider } from "./types";

export type { PublicKeyInfo, SignResult, SigningProvider } from "./types";
export { LocalKeyProvider, LOCAL_ALG } from "./local";
export { AwsKmsProvider } from "./aws-kms";

let provider: SigningProvider | null = null;

export function getSigningProvider(): SigningProvider {
  if (!provider) {
    const kind = (process.env.SIGNING_PROVIDER ?? "local").toLowerCase();
    if (kind === "aws-kms" || kind === "kms") {
      provider = new AwsKmsProvider();
    } else {
      provider = new LocalKeyProvider();
    }
  }
  return provider;
}

/** Override provider (tests). */
export function setSigningProvider(next: SigningProvider | null): void {
  provider = next;
}

/**
 * Ensure every public key from the provider is persisted.
 * Never deletes rows — rotation only adds / sets validTo.
 */
export async function syncPublicKeysToDb(
  signing: SigningProvider = getSigningProvider(),
): Promise<PublicKeyInfo[]> {
  const keys = await signing.getPublicKeys();
  for (const key of keys) {
    const existing = await prisma.publicKeyRecord.findUnique({
      where: { keyId: key.keyId },
    });
    if (!existing) {
      try {
        await prisma.publicKeyRecord.create({
          data: {
            keyId: key.keyId,
            alg: key.alg,
            publicKey: key.publicKey,
            validFrom: key.validFrom,
            validTo: key.validTo,
          },
        });
      } catch (err) {
        // Concurrent syncs may race on the same keyId — treat as already present.
        if (
          !(
            err &&
            typeof err === "object" &&
            "code" in err &&
            (err as { code: string }).code === "P2002"
          )
        ) {
          throw err;
        }
      }
    } else if (
      (existing.validTo == null) !== (key.validTo == null) ||
      (existing.validTo &&
        key.validTo &&
        existing.validTo.getTime() !== key.validTo.getTime())
    ) {
      await prisma.publicKeyRecord.update({
        where: { keyId: key.keyId },
        data: { validTo: key.validTo },
      });
    }
  }
  return keys;
}

/** Public keys for /.well-known/doc-detective/keys.json (DB ∪ provider). */
export async function listPublishedKeys(): Promise<
  Array<{
    keyId: string;
    alg: string;
    publicKey: string;
    validFrom: string;
    validTo: string | null;
  }>
> {
  await syncPublicKeysToDb();
  const rows = await prisma.publicKeyRecord.findMany({
    orderBy: { validFrom: "asc" },
  });
  return rows.map((r) => ({
    keyId: r.keyId,
    alg: r.alg,
    publicKey: r.publicKey,
    validFrom: r.validFrom.toISOString(),
    validTo: r.validTo ? r.validTo.toISOString() : null,
  }));
}
