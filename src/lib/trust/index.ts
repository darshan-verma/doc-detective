export {
  generateCertId,
  formatCertId,
  normalizeCertId,
  isLegacyCertId,
  isValidCertIdFormat,
  watermarkTokenFromCertId,
} from "./ids";

export {
  getSigningProvider,
  setSigningProvider,
  listPublishedKeys,
  syncPublicKeysToDb,
  LocalKeyProvider,
  AwsKmsProvider,
  LOCAL_ALG,
} from "./keys";
export type { SigningProvider, SignResult, PublicKeyInfo } from "./keys";

export {
  appendLogEntry,
  verifyLogChain,
  computeEntryHash,
  hashCertificateRecord,
  GENESIS_PREV_HASH,
} from "./log";
export type { LogEventType, ChainVerifyResult } from "./log";

export {
  buildMerkleTree,
  getMerkleRoot,
  getInclusionProof,
  verifyInclusionProof,
  hashLeaf,
  hashNode,
} from "./merkle";
export type { MerkleInclusionProof, MerkleProofStep } from "./merkle";

export {
  runCheckpointJob,
  getProofBundle,
  DEFAULT_TSA_URL,
} from "./timestamp/checkpoint";

export {
  buildTimeStampRequest,
  buildMockTimeStampResponse,
  verifyTimeStampResponse,
  merkleRootMessageImprint,
} from "./timestamp/rfc3161";

export {
  getRateLimiter,
  setRateLimiter,
  rateLimit,
  resetRateLimits,
  clientKey,
  MemoryRateLimiter,
  RedisRateLimiter,
} from "./rate-limit";
export type { RateLimiter, RateLimitResult } from "./rate-limit";
