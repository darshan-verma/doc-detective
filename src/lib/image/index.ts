export {
  decodeImage,
  encodePng,
  encodeJpeg,
  resizePixels,
  isCertifiableImage,
  aspectDiffers,
  aspectRatio,
} from "./codec";
export {
  phash64,
  hamming,
  cellSignatures,
  compareCells,
  classifyImageChange,
  type CellSignature,
  type CellCompareResult,
  type ChangedCellDetail,
  type ChangedCellCluster,
  type ImageChangeClass,
  type ClassifyImageChangeConfig,
  type ClassifyImageChangeResult,
} from "./fingerprint";
export {
  embed,
  embedCertId,
  extract,
  encodePayload,
  decodePayload,
  WATERMARK_VERSION,
  PAYLOAD_BITS,
  type ExtractResult,
} from "./watermark";
export type { PixelBuffer } from "./pixels";
