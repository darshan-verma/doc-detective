"use client";

import { useCallback, useState } from "react";
import { FileDropzone } from "@/components/FileDropzone";

export interface IdentifySignalView {
  type: string;
  label: string;
  weak?: boolean;
  confidence?: number;
  hamming?: number;
}

export interface IdentifyCandidateView {
  certId: string;
  signals: IdentifySignalView[];
  score: number;
  filenameOnly: boolean;
  strong: boolean;
  certificate: {
    certId: string;
    certIdDisplay?: string;
    createdAt: string;
    timestampStatus?: string;
    signatureAlg?: string;
    sha256?: string;
    revokedAt?: string | null;
  };
}

export type IdentifyApiResult =
  | {
      kind: "EXACT";
      matchedOn: "sha256" | "inputSha256";
      certificate: {
        certId: string;
        certIdDisplay?: string;
        createdAt: string;
        timestampStatus?: string;
        signatureAlg?: string;
        sha256?: string;
        revokedAt?: string | null;
      };
      revoked: boolean;
      revokeReason: string | null;
    }
  | {
      kind: "LIKELY_MODIFIED_COPY";
      candidates: IdentifyCandidateView[];
      warnings?: string[];
    }
  | {
      kind: "NEW";
      warnings?: string[];
    };

interface IdentifyUploadProps {
  disabled?: boolean;
  /** Show the currently selected file in the dropzone. */
  selectedFile?: File | null;
  onClear?: () => void;
  onIdentified: (file: File, result: IdentifyApiResult) => void;
  onError?: (message: string) => void;
  onBusyChange?: (busy: boolean) => void;
}

/** Shared upload + identify call for /certify and /verify. */
export function IdentifyUpload({
  disabled,
  selectedFile,
  onClear,
  onIdentified,
  onError,
  onBusyChange,
}: IdentifyUploadProps) {
  const [busy, setBusy] = useState(false);

  const run = useCallback(
    async (file: File) => {
      setBusy(true);
      onBusyChange?.(true);
      try {
        const form = new FormData();
        form.append("file", file);
        const res = await fetch("/api/identify", { method: "POST", body: form });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data?.error?.message || "Identify failed");
        }
        onIdentified(file, data as IdentifyApiResult);
      } catch (err) {
        onError?.(err instanceof Error ? err.message : "Identify failed");
      } finally {
        setBusy(false);
        onBusyChange?.(false);
      }
    },
    [onBusyChange, onError, onIdentified],
  );

  return (
    <FileDropzone
      onFile={run}
      disabled={disabled || busy}
      selectedFile={selectedFile}
      onClear={onClear}
    />
  );
}
