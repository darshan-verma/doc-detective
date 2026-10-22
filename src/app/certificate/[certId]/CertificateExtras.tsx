"use client";

import { useEffect, useState } from "react";

export function CertificateQr({ certId }: { certId: string }) {
  const [src, setSrc] = useState<string | null>(null);

  useEffect(() => {
    const url = `${window.location.origin}/v/${certId}`;
    void import("qrcode").then(async (QRCode) => {
      const dataUrl = await QRCode.toDataURL(url, { width: 160, margin: 1 });
      setSrc(dataUrl);
    });
  }, [certId]);

  if (!src) return null;
  return (
    <div className="space-y-2">
      <p className="text-xs uppercase tracking-wider text-zinc-500">
        Verification QR
      </p>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={src} alt={`QR for ${certId}`} width={160} height={160} />
      <p className="font-mono text-xs text-zinc-500">/v/{certId}</p>
    </div>
  );
}
