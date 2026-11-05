import type { ValidationStatus } from "@/lib/api";

const COPY: Partial<Record<ValidationStatus, { title: string; body: string }>> = {
  INVALID_TAMPERED: {
    title: "Alerta: este documento foi alterado depois de assinado",
    body: "O conteúdo do PDF não corresponde mais à assinatura digital. Não confie neste arquivo. Para obter a via autêntica, consulte o certificado pelo código.",
  },
  INVALID_SIGNATURE: {
    title: "Atenção: a assinatura deste PDF não é reconhecida",
    body: "O arquivo não contém uma assinatura digital válida emitida por esta plataforma. Ele pode não ser um certificado autêntico.",
  },
};

export function TamperAlert({ status }: { status: ValidationStatus }) {
  const copy = COPY[status];
  if (!copy) return null;
  return (
    <div role="alert" className="border-2 border-danger bg-danger-wash p-5 text-danger">
      <p className="text-base font-bold">{copy.title}</p>
      <p className="mt-1 max-w-reading text-sm text-ink">{copy.body}</p>
    </div>
  );
}
