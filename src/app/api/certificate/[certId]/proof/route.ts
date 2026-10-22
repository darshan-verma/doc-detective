import {
  getCertificateById,
  notFoundCertificateResponse,
} from "@/lib/certificates/service";
import { errorResponse } from "@/lib/errors";
import { isValidCertIdFormat, normalizeCertId } from "@/lib/trust/ids";
import { getProofBundle } from "@/lib/trust/timestamp/checkpoint";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Downloadable offline proof bundle (JSON + embedded .tsr token base64). */
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
    if (!cert) return notFoundCertificateResponse();

    const bundle = await getProofBundle(certId);
    return Response.json(bundle, {
      headers: {
        "Content-Disposition": `attachment; filename="doc-detective-proof-${certId}.json"`,
      },
    });
  } catch (err) {
    return errorResponse(err);
  }
}
