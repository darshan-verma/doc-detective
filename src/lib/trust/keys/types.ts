export interface PublicKeyInfo {
  keyId: string;
  alg: string;
  publicKey: string; // SPKI PEM
  validFrom: Date;
  validTo: Date | null;
}

export interface SignResult {
  signature: string; // base64
  keyId: string;
  alg: string;
}

export interface SigningProvider {
  sign(bytes: Buffer | Uint8Array): Promise<SignResult>;
  getPublicKeys(): Promise<PublicKeyInfo[]>;
  /** Active key used for new signatures. */
  getActiveKeyId(): Promise<string>;
}
