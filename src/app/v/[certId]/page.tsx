import { redirect } from "next/navigation";
import { isValidCertIdFormat, normalizeCertId } from "@/lib/trust/ids";

export const dynamic = "force-dynamic";

/** Short verification URL — preloads the certificate on /verify. */
export default async function ShortVerifyPage({
  params,
}: {
  params: Promise<{ certId: string }>;
}) {
  const { certId: raw } = await params;
  if (!isValidCertIdFormat(raw)) {
    redirect("/verify");
  }
  const certId = normalizeCertId(raw)!;
  redirect(`/verify?certId=${encodeURIComponent(certId)}`);
}
