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
  type CellSignature,
  type CellCompareResult,
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
