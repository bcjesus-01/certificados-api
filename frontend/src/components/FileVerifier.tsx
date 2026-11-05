"use client";

import { useRef, useState } from "react";

import { ApiError, validateFile, type FileValidation } from "@/lib/api";

import { CertificateDetails } from "./CertificateDetails";
import { CryptoReport } from "./CryptoReport";
import { ErrorNotice } from "./ErrorNotice";
import { FileDropzone } from "./FileDropzone";
import { Seal } from "./Seal";
import { TamperAlert } from "./TamperAlert";
import { Verdict } from "./Verdict";

type State =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "done"; result: FileValidation }
  | { phase: "error"; message: string };

export function FileVerifier() {
  const [state, setState] = useState<State>({ phase: "idle" });
  const latest = useRef(0);

  const verify = async (file: File): Promise<void> => {
    const ticket = ++latest.current;
    setState({ phase: "loading" });
    try {
      const result = await validateFile(file);
      if (ticket === latest.current) setState({ phase: "done", result });
    } catch (error: unknown) {
      if (ticket !== latest.current) return;
      const message = error instanceof ApiError ? error.message : "Erro inesperado ao examinar o arquivo.";
      setState({ phase: "error", message });
    }
  };

  const loading = state.phase === "loading";

  return (
    <div className="space-y-6">
      <FileDropzone disabled={loading} onFile={(file) => void verify(file)} />

      {state.phase === "idle" ? (
        <p className="max-w-reading text-sm text-ink-soft">
          A perícia confere o hash do arquivo com os certificados emitidos e verifica a assinatura digital PAdES. O PDF
          não é guardado.
        </p>
      ) : null}

      {loading ? (
        <div role="status" className="flex items-center gap-4 border-l-4 border-rule bg-paper p-5 text-ink-soft">
          <Seal state="loading" size={72} />
          <p className="text-sm">Examinando a assinatura digital…</p>
        </div>
      ) : null}

      {state.phase === "error" ? <ErrorNotice message={state.message} /> : null}

      {state.phase === "done" ? (
        <article className="space-y-4">
          <TamperAlert status={state.result.status} />
          <div className="border border-rule">
            <Verdict level={2} status={state.result.status} message={state.result.message} />
            {state.result.certificate ? <CertificateDetails certificate={state.result.certificate} /> : null}
            <CryptoReport
              report={state.result.crypto}
              fileSha256={state.result.file_sha256}
              fileSizeBytes={state.result.file_size_bytes}
            />
          </div>
        </article>
      ) : null}
    </div>
  );
}
