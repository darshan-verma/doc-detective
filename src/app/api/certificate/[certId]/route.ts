import {
  assertRecordIntegrity,
  getCertificateById,
  notFoundCertificateResponse,
  publicCertificateView,
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

    const certId = normalizeCertId(raw)!;
    const cert = await getCertificateById(certId);
    if (!cert) {
      return notFoundCertificateResponse();
    }

    await assertRecordIntegrity(cert);
    return Response.json(publicCertificateView(cert));
  } catch (err) {
    return errorResponse(err);
  }
}
