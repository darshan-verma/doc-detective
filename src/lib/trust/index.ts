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
  verifyLogEntries,
  verifyAndRecordLogChain,
  recordLogChainStatus,
  getLogChainStatus,
  computeEntryHash,
  recomputeStoredEntryHash,
  hashCertificateRecord,
  hashRevokeRecord,
  checkCertificateRevocation,
  evaluateRevocationFromEntries,
  evaluateCertificateLogFromEntries,
  revokeDisplayMessage,
  isEntryHashValid,
  assessEntriesIntegrity,
  brokenLogChainMessage,
  applyLogIntegrityToVerifyResponse,
  GENESIS_PREV_HASH,
  LOG_ENTRY_DOMAIN_V2,
  LOG_CHAIN_STATUS_ID,
  LOG_HEAD_ID,
} from "./log";
export type {
  LogEventType,
  ChainVerifyResult,
  RevocationLogCheck,
  EntryIntegrity,
  LogIntegrity,
} from "./log";

export {
  LogHeadConflict,
  withTxRetry,
  isRetryableTxError,
  isLogEntrySeqUniqueViolation,
} from "./tx-retry";
export type { WithTxRetryOptions } from "./tx-retry";

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
