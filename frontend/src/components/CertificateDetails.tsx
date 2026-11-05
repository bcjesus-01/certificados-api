import type { ReactNode } from "react";

import type { PublicCertificate } from "@/lib/api";
import { formatDate, formatDateTime, formatHours } from "@/lib/format";

import { CopyButton } from "./CopyButton";

function Row({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 border-b border-rule py-3 sm:grid-cols-[11rem_1fr] sm:gap-4">
      <dt className="text-sm text-ink-soft">{term}</dt>
      <dd className="min-w-0 break-words text-sm font-medium">{children}</dd>
    </div>
  );
}

function Mono({ text, copyLabel }: { text: string; copyLabel: string }) {
  return (
    <span className="flex flex-wrap items-center gap-2">
      <code className="break-all font-mono text-xs font-normal">{text}</code>
      <CopyButton value={text} label={copyLabel} />
    </span>
  );
}

export function CertificateDetails({ certificate }: { certificate: PublicCertificate }) {
  return (
    <dl className="border-t border-rule bg-paper px-5">
      <Row term="Participante">{certificate.recipient_name}</Row>
      {certificate.recipient_doc ? <Row term="Documento">{certificate.recipient_doc}</Row> : null}
      <Row term="Participação">{certificate.role}</Row>
      <Row term="Evento">{certificate.event_name}</Row>
      <Row term="Data do evento">{formatDate(certificate.event_date)}</Row>
      <Row term="Carga horária">{formatHours(certificate.workload_hours)}</Row>
      <Row term="Emitido em">{formatDateTime(certificate.issued_at)}</Row>
      {certificate.revoked ? <Row term="Revogado em">{formatDateTime(certificate.revoked_at)}</Row> : null}
      <Row term="Código">
        <Mono text={certificate.cert_uuid} copyLabel="Copiar código do certificado" />
      </Row>
      <Row term="SHA-256 do PDF">
        <Mono text={certificate.file_sha256} copyLabel="Copiar hash SHA-256" />
      </Row>
    </dl>
  );
}
