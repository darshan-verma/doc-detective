import { AppError, errorResponse } from "@/lib/errors";
import { prisma } from "@/lib/prisma";
import { buildVerificationReportPdf } from "@/lib/report";
import { Verdict, type AnalysisResult } from "@/lib/analysis/types";

export const runtime = "nodejs";

/**
 * Generate a verification report PDF from derived analysis data only.
 * Does not accept or require the uploaded file — only the stored analysis result.
 * Body: { certId, verdict, uploadedSha256, registeredSha256, analysis?, ... }
 */
export async function POST(request: Request) {
  try {
    const body = (await request.json()) as {
      certId?: string;
      verdict?: string;
      uploadedSha256?: string;
      registeredSha256?: string;
      analysis?: AnalysisResult;
      signatureValid?: boolean;
      timestampStatus?: string;
      tsaGenTime?: string | null;
      revoked?: boolean;
    };

    if (!body.certId || !body.uploadedSha256 || !body.registeredSha256) {
      throw new AppError("BAD_REQUEST", "Missing required report fields", 400);
    }

    const { pdf, sha256 } = await buildVerificationReportPdf({
      certId: body.certId,
      verdict: body.verdict ?? Verdict.TAMPERED,
      analysis: body.analysis,
      signatureValid: body.signatureValid,
      timestampStatus: body.timestampStatus,
      tsaGenTime: body.tsaGenTime,
      registeredSha256: body.registeredSha256,
      uploadedSha256: body.uploadedSha256,
      revoked: body.revoked,
    });

    await prisma.verificationLog.create({
      data: {
        certId: body.certId,
        result: `REPORT:${body.verdict ?? "UNKNOWN"}`,
        uploadedSha256: body.uploadedSha256,
        reportSha256: sha256,
      },
    });

    return new Response(new Uint8Array(pdf), {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="doc-detective-report-${body.certId}.pdf"`,
        "X-Report-SHA256": sha256,
      },
    });
  } catch (err) {
    console.error("[api/verify/report] full error:", err);
    if (err instanceof Error && !(err instanceof AppError)) {
      return Response.json(
        {
          error: {
            code: "INTERNAL",
            message: err.message || "Report generation failed",
          },
        },
        { status: 500 },
      );
    }
    return errorResponse(err);
  }
}
