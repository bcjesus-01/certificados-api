import type { ReactNode } from "react";

import type { CryptoReport as Report } from "@/lib/api";
import { formatBytes, formatDateTime } from "@/lib/format";

import { CopyButton } from "./CopyButton";

type Tri = boolean | null;

function Check({ label, hint, value }: { label: string; hint: string; value: Tri }) {
  const text = value === null ? "Não avaliado" : value ? "Sim" : "Não";
  const tone = value === null ? "text-ink-soft" : value ? "text-valid" : "text-danger";
  const mark = value === null ? "–" : value ? "✓" : "✕";
  return (
    <div className="grid grid-cols-[1fr_auto] gap-x-4 border-b border-rule py-3">
      <dt className="text-sm font-medium">{label}</dt>
      <dd className={`text-sm font-semibold ${tone}`}>
        <span aria-hidden="true">{mark} </span>
        {text}
      </dd>
      <p className="col-span-2 mt-0.5 text-xs text-ink-soft">{hint}</p>
    </div>
  );
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 border-b border-rule py-3 sm:grid-cols-[11rem_1fr] sm:gap-4">
      <dt className="text-sm text-ink-soft">{term}</dt>
      <dd className="min-w-0 break-words text-sm">{children}</dd>
    </div>
  );
}

interface CryptoReportProps {
  report: Report;
  fileSha256: string;
  fileSizeBytes: number;
}

export function CryptoReport({ report, fileSha256, fileSizeBytes }: CryptoReportProps) {
  return (
    <section aria-labelledby="laudo-titulo" className="border-t border-rule bg-paper px-5 pb-2 pt-5">
      <h3 id="laudo-titulo" className="font-display text-xl font-semibold">
        Laudo técnico da assinatura
      </h3>
      {report.summary ? <p className="mt-1 max-w-reading text-sm text-ink-soft">{report.summary}</p> : null}

      <dl className="mt-3">
        <Check
          label="Integridade binária"
          hint="Os bytes assinados continuam idênticos aos do momento da assinatura."
          value={report.intact}
        />
        <Check
          label="Assinatura válida"
          hint="A assinatura criptográfica confere com o certificado do emissor."
          value={report.valid}
        />
        <Check
          label="Cadeia confiável"
          hint="O certificado X.509 do emissor pertence à cadeia desta plataforma."
          value={report.trusted}
        />
        <Check
          label="Cobre o arquivo inteiro"
          hint="Nada foi anexado ao PDF depois da assinatura."
          value={report.covers_entire_file}
        />
        <Check
          label="Hash igual ao registro"
          hint="O SHA-256 do arquivo bate com o certificado emitido."
          value={report.hash_matches_record}
        />
        <Check
          label="Emissor igual ao registro"
          hint="O certificado que assinou é o mesmo registrado na emissão."
          value={report.signer_matches_record}
        />
      </dl>

      <dl className="mt-2">
        <Fact term="SHA-256 calculado">
          <span className="flex flex-wrap items-center gap-2">
            <code className="break-all font-mono text-xs">{fileSha256}</code>
            <CopyButton value={fileSha256} label="Copiar hash calculado" />
          </span>
        </Fact>
        <Fact term="Tamanho">{formatBytes(fileSizeBytes)}</Fact>
        <Fact term="Assinaturas no PDF">{report.signature_count}</Fact>
        <Fact term="Certificado emissor (X.509)">
          {report.signer_fingerprint ? (
            <span className="flex flex-col gap-1">
              <span className="text-xs text-ink-soft">Impressão digital SHA-256</span>
              <code className="break-all font-mono text-xs">{report.signer_fingerprint}</code>
              <span className="text-xs text-ink-soft">
                O nome do titular do certificado é omitido de propósito, por privacidade (LGPD).
              </span>
            </span>
          ) : (
            "Nenhum certificado de assinatura encontrado"
          )}
        </Fact>
        <Fact term="Verificado em">{formatDateTime(report.evaluated_at)}</Fact>
      </dl>

      {report.findings.length > 0 ? (
        <div className="py-4">
          <h4 className="text-sm font-semibold">Observações da perícia</h4>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
            {report.findings.map((finding) => (
              <li key={finding}>{finding}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
