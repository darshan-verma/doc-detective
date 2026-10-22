import { revokeCertificate } from "@/lib/certificates/ownership";
import { notFoundCertificateResponse } from "@/lib/certificates/service";
import { AppError, errorResponse } from "@/lib/errors";
import { isValidCertIdFormat, normalizeCertId } from "@/lib/trust/ids";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  context: { params: Promise<{ certId: string }> },
) {
  try {
    const { certId: raw } = await context.params;
    if (!raw || !isValidCertIdFormat(raw)) {
      return notFoundCertificateResponse();
    }
    const certId = normalizeCertId(raw)!;
    const body = (await request.json().catch(() => ({}))) as {
      ownerToken?: string;
      reason?: string;
    };
    if (!body.ownerToken) {
      throw new AppError("BAD_REQUEST", "ownerToken is required", 400);
    }
    await revokeCertificate(
      certId,
      body.ownerToken,
      body.reason ?? "Revoked by owner",
    );
    return Response.json({ ok: true, certId, revoked: true });
  } catch (err) {
    return errorResponse(err);
  }
}
