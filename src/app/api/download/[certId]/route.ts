import {
  getCertificateById,
  notFoundCertificateResponse,
  streamStoredFileToResponse,
} from "@/lib/certificates/service";
import { errorResponse } from "@/lib/errors";
import { isValidCertIdFormat, normalizeCertId } from "@/lib/trust/ids";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  context: { params: Promise<{ certId: string }> },
) {
  try {
    const { certId: raw } = await context.params;
    if (!raw || !isValidCertIdFormat(raw)) {
      return notFoundCertificateResponse();
    }

    const cert = await getCertificateById(normalizeCertId(raw)!);
    if (!cert) {
      return notFoundCertificateResponse();
    }

    return streamStoredFileToResponse(cert);
  } catch (err) {
    return errorResponse(err);
  }
}
