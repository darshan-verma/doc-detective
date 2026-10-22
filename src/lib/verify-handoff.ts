/**
 * Browser-only handoff: certify → verify with the same file + certId
 * so verification can auto-run without re-uploading.
 */
export const VERIFY_HANDOFF_KEY = "doc-detective-verify-handoff";

export interface VerifyHandoffPayload {
  certId: string;
  fileName: string;
  mimeType: string;
  /** Base64 of file bytes */
  fileBase64: string;
  createdAt: number;
}

const MAX_HANDOFF_AGE_MS = 10 * 60 * 1000;

export async function storeVerifyHandoff(
  file: File,
  certId: string,
): Promise<void> {
  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  const payload: VerifyHandoffPayload = {
    certId,
    fileName: file.name,
    mimeType: file.type || "application/octet-stream",
    fileBase64: btoa(binary),
    createdAt: Date.now(),
  };
  sessionStorage.setItem(VERIFY_HANDOFF_KEY, JSON.stringify(payload));
}

export function consumeVerifyHandoff(): {
  file: File;
  certId: string;
} | null {
  try {
    const raw = sessionStorage.getItem(VERIFY_HANDOFF_KEY);
    if (!raw) return null;
    sessionStorage.removeItem(VERIFY_HANDOFF_KEY);
    const payload = JSON.parse(raw) as VerifyHandoffPayload;
    if (!payload?.fileBase64 || !payload.certId) return null;
    if (Date.now() - (payload.createdAt || 0) > MAX_HANDOFF_AGE_MS) return null;

    const binary = atob(payload.fileBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const file = new File([bytes], payload.fileName || "upload", {
      type: payload.mimeType || "application/octet-stream",
    });
    return { file, certId: payload.certId };
  } catch {
    try {
      sessionStorage.removeItem(VERIFY_HANDOFF_KEY);
    } catch {
      /* ignore */
    }
    return null;
  }
}
