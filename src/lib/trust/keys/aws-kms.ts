import type { PublicKeyInfo, SignResult, SigningProvider } from "./types";

/**
 * Stub AWS KMS signing provider. Selected when SIGNING_PROVIDER=aws-kms.
 * Wire up @aws-sdk/client-kms in production; this stub fails loudly so
 * misconfiguration is obvious in local/dev.
 */
export class AwsKmsProvider implements SigningProvider {
  private readonly keyId: string;

  constructor(keyId?: string) {
    this.keyId = keyId ?? process.env.AWS_KMS_KEY_ID ?? "aws-kms-unconfigured";
  }

  async getActiveKeyId(): Promise<string> {
    return this.keyId;
  }

  async sign(_bytes: Buffer | Uint8Array): Promise<SignResult> {
    throw new Error(
      "AwsKmsProvider is a stub. Set SIGNING_PROVIDER=local for development, or implement KMS Sign.",
    );
  }

  async getPublicKeys(): Promise<PublicKeyInfo[]> {
    throw new Error(
      "AwsKmsProvider is a stub. Set SIGNING_PROVIDER=local for development, or implement KMS GetPublicKey.",
    );
  }
}
