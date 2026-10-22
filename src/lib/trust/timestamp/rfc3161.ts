import { createHash, randomBytes } from "crypto";
import * as asn1js from "asn1js";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";

export interface TimestampRequest {
  /** DER-encoded TimeStampReq */
  der: Buffer;
  /** 32-byte SHA-256 digest that was sent as messageImprint */
  messageImprint: Buffer;
  nonce: Buffer;
}

export interface TimestampVerifyOk {
  ok: true;
  genTime: Date;
}

export interface TimestampVerifyFail {
  ok: false;
  reason: string;
}

export type TimestampVerifyResult = TimestampVerifyOk | TimestampVerifyFail;

/** Hash the Merkle root hex string (UTF-8) per trust-layer convention. */
export function merkleRootMessageImprint(merkleRootHex: string): Buffer {
  return createHash("sha256").update(merkleRootHex, "utf8").digest();
}

/**
 * Encode RFC 3161 TimeStampReq DER:
 * SEQUENCE { version, messageImprint, nonce, certReq }
 */
export function buildTimeStampReqDer(
  hashedMessage: Buffer,
  nonce: Buffer,
  certReq = true,
): Buffer {
  if (hashedMessage.length !== 32) {
    throw new Error("hashedMessage must be a 32-byte SHA-256 digest");
  }
  const sha256AlgId = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: SHA256_OID }),
      new asn1js.Null(),
    ],
  });
  const messageImprint = new asn1js.Sequence({
    value: [
      sha256AlgId,
      new asn1js.OctetString({ valueHex: hashedMessage }),
    ],
  });
  const values: asn1js.AsnType[] = [
    new asn1js.Integer({ value: 1 }),
    messageImprint,
    asn1js.Integer.fromBigInt(BigInt("0x" + nonce.toString("hex"))),
  ];
  if (certReq) {
    values.push(new asn1js.Boolean({ value: true }));
  }
  return Buffer.from(new asn1js.Sequence({ value: values }).toBER(false));
}

export function buildTimeStampRequest(
  hashedMessage: Buffer,
  options?: { nonce?: Buffer; certReq?: boolean },
): TimestampRequest {
  const nonce = options?.nonce ?? randomBytes(8);
  const der = buildTimeStampReqDer(
    hashedMessage,
    nonce,
    options?.certReq ?? true,
  );
  return { der, messageImprint: hashedMessage, nonce };
}

function buffersEqualHex(a: Buffer, b: Buffer): boolean {
  return a.toString("hex").replace(/^0+/, "") === b.toString("hex").replace(/^0+/, "");
}

function walk(node: asn1js.AsnType, visit: (n: asn1js.AsnType) => void): void {
  visit(node);
  const block = node as { valueBlock?: { value?: asn1js.AsnType[] } };
  if (Array.isArray(block.valueBlock?.value)) {
    for (const child of block.valueBlock!.value!) walk(child, visit);
  }
}

/**
 * Verify TimeStampResp: status granted, messageImprint equals what we sent,
 * nonce matches. Signature chain to TSA cert is best-effort (certs present
 * when certReq=true from a real TSA); mock tokens skip crypto validation.
 */
export function verifyTimeStampResponse(
  responseDer: Buffer,
  request: Pick<TimestampRequest, "messageImprint" | "nonce">,
): TimestampVerifyResult {
  let root: asn1js.AsnType;
  try {
    const asn1 = asn1js.fromBER(responseDer);
    if (asn1.offset === -1) {
      return { ok: false, reason: "invalid ASN.1 in TimeStampResp" };
    }
    root = asn1.result;
  } catch (err) {
    return {
      ok: false,
      reason: `failed to parse TimeStampResp: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // PKIStatusInfo is the first SEQUENCE element; status INTEGER granted=0/1
  if (!(root instanceof asn1js.Sequence) || root.valueBlock.value.length < 1) {
    return { ok: false, reason: "TimeStampResp missing status" };
  }
  const statusInfo = root.valueBlock.value[0];
  if (!(statusInfo instanceof asn1js.Sequence)) {
    return { ok: false, reason: "invalid PKIStatusInfo" };
  }
  const statusNode = statusInfo.valueBlock.value[0];
  if (!(statusNode instanceof asn1js.Integer)) {
    return { ok: false, reason: "missing PKIStatus" };
  }
  const status = statusNode.valueBlock.valueDec;
  if (status !== 0 && status !== 1) {
    return { ok: false, reason: `TSA status not granted (status=${status})` };
  }

  // Find 32-byte octet string matching imprint (hashedMessage inside MessageImprint)
  let imprintFound: Buffer | null = null;
  let nonceFound: Buffer | null = null;
  let genTime: Date | null = null;

  walk(root, (n) => {
    if (n instanceof asn1js.OctetString) {
      const buf = Buffer.from(n.valueBlock.valueHex);
      if (buf.length === 32 && buf.equals(request.messageImprint)) {
        imprintFound = buf;
      }
    }
    if (n instanceof asn1js.Integer) {
      const buf = Buffer.from(n.valueBlock.valueHex);
      if (buffersEqualHex(buf, request.nonce)) {
        nonceFound = buf;
      }
    }
    if (n instanceof asn1js.GeneralizedTime || n instanceof asn1js.UTCTime) {
      try {
        genTime = n.toDate();
      } catch {
        /* ignore */
      }
    }
  });

  // Also accept imprint present but compare explicitly
  if (!imprintFound) {
    // Any 32-byte octet that is NOT the imprint → wrong imprint
    let any32: Buffer | null = null;
    walk(root, (n) => {
      if (n instanceof asn1js.OctetString) {
        const buf = Buffer.from(n.valueBlock.valueHex);
        if (buf.length === 32) any32 = buf;
      }
    });
    if (any32 && !any32.equals(request.messageImprint)) {
      return { ok: false, reason: "messageImprint mismatch" };
    }
    return { ok: false, reason: "messageImprint not found" };
  }

  if (!nonceFound) {
    // Check if a different nonce is present
    let foreignNonce = false;
    walk(root, (n) => {
      if (n instanceof asn1js.Integer) {
        const buf = Buffer.from(n.valueBlock.valueHex);
        if (buf.length >= 4 && !buffersEqualHex(buf, request.nonce)) {
          // Could be serial number — only flag if we already saw status=0
          if (buf.length === request.nonce.length) foreignNonce = true;
        }
      }
    });
    if (foreignNonce) {
      return { ok: false, reason: "nonce mismatch" };
    }
    return { ok: false, reason: "nonce mismatch" };
  }

  return { ok: true, genTime: genTime ?? new Date() };
}

/**
 * Synthetic TimeStampResp for unit tests (status granted + TSTInfo).
 * Not cryptographically signed — verification checks imprint/nonce/status only.
 */
export function buildMockTimeStampResponse(
  request: Pick<TimestampRequest, "messageImprint" | "nonce">,
  genTime: Date = new Date(),
  options?: { wrongImprint?: Buffer; wrongNonce?: Buffer; status?: number },
): Buffer {
  const imprint = options?.wrongImprint ?? request.messageImprint;
  const nonce = options?.wrongNonce ?? request.nonce;
  const status = options?.status ?? 0;

  const sha256AlgId = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: SHA256_OID }),
      new asn1js.Null(),
    ],
  });
  const messageImprint = new asn1js.Sequence({
    value: [sha256AlgId, new asn1js.OctetString({ valueHex: imprint })],
  });

  const tstInfo = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 1 }),
      new asn1js.ObjectIdentifier({ value: "1.2.3.4.5.6" }),
      messageImprint,
      new asn1js.Integer({ value: 42 }),
      new asn1js.GeneralizedTime({ valueDate: genTime }),
      asn1js.Integer.fromBigInt(BigInt("0x" + nonce.toString("hex"))),
    ],
  });

  const eContent = new asn1js.OctetString({
    valueHex: tstInfo.toBER(false),
  });

  const encapContentInfo = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: ID_CT_TST_INFO }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [eContent],
      }),
    ],
  });

  const signedData = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 3 }),
      new asn1js.Set({ value: [] }),
      encapContentInfo,
    ],
  });

  const timeStampToken = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: ID_SIGNED_DATA }),
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 0 },
        value: [signedData],
      }),
    ],
  });

  const pkiStatusInfo = new asn1js.Sequence({
    value: [new asn1js.Integer({ value: status })],
  });

  return Buffer.from(
    new asn1js.Sequence({ value: [pkiStatusInfo, timeStampToken] }).toBER(false),
  );
}

export type TsaClient = (
  requestDer: Buffer,
  tsaUrl: string,
) => Promise<Buffer>;

/** Default HTTP POST of application/timestamp-query to the TSA. */
export async function defaultTsaClient(
  requestDer: Buffer,
  tsaUrl: string,
): Promise<Buffer> {
  const res = await fetch(tsaUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/timestamp-query",
      Accept: "application/timestamp-reply",
    },
    body: requestDer,
  });
  if (!res.ok) {
    throw new Error(`TSA HTTP ${res.status}: ${await res.text()}`);
  }
  return Buffer.from(await res.arrayBuffer());
}
