"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, validateByCode, type CodeValidation } from "@/lib/api";
import { extractUuid } from "@/lib/format";

import { CertificateDetails } from "./CertificateDetails";
import { DownloadButton } from "./DownloadButton";
import { ErrorNotice } from "./ErrorNotice";
import { Seal } from "./Seal";
import { Verdict } from "./Verdict";

type State =
  | { phase: "loading" }
  | { phase: "done"; result: CodeValidation }
  | { phase: "error"; message: string };

interface CodeResultProps {
  code: string;
  level: 1 | 2;
}

export function CodeResult({ code, level }: CodeResultProps) {
  const [state, setState] = useState<State>({ phase: "loading" });
  const [attempt, setAttempt] = useState(0);
  const uuid = extractUuid(code);

  useEffect(() => {
    if (!uuid) return;
    let cancelled = false;
    setState({ phase: "loading" });
    validateByCode(uuid)
      .then((result) => {
        if (!cancelled) setState({ phase: "done", result });
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        const message = error instanceof ApiError ? error.message : "Erro inesperado ao consultar o certificado.";
        setState({ phase: "error", message });
      });
    return () => {
      cancelled = true;
    };
  }, [uuid, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  if (!uuid) {
    return (
      <Verdict
        level={level}
        status="NOT_FOUND"
        message="Esse código não tem o formato de um certificado (um UUID, como 3f2b8c1e-…). Confira se copiou o código inteiro ou escaneie o QR Code do certificado."
      />
    );
  }

  if (state.phase === "loading") {
    return (
      <div role="status" className="flex items-center gap-4 border-l-4 border-rule bg-paper p-5 text-ink-soft">
        <Seal state="loading" size={72} />
        <p className="text-sm">Consultando o certificado…</p>
      </div>
    );
  }

  if (state.phase === "error") {
    return <ErrorNotice message={state.message} onRetry={retry} />;
  }

  const { result } = state;
  return (
    <article className="border border-rule">
      <Verdict level={level} status={result.status} message={result.message} />
      {result.certificate ? <CertificateDetails certificate={result.certificate} /> : null}
      {result.download ? <DownloadButton link={result.download} /> : null}
    </article>
  );
}
