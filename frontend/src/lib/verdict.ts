/** Mapeamento do status canônico da API para o selo, o título e as cores do veredito. */

import type { ValidationStatus } from "./api";

export type SealState = "idle" | "loading" | "valid" | "revoked" | "not_found" | "tampered" | "invalid";

export interface VerdictStyle {
  title: string;
  seal: SealState;
  /** Classes completas (o Tailwind precisa vê-las literalmente). */
  text: string;
  wash: string;
  border: string;
}

export const VERDICTS: Record<ValidationStatus, VerdictStyle> = {
  VALID: {
    title: "Certificado válido",
    seal: "valid",
    text: "text-valid",
    wash: "bg-valid-wash",
    border: "border-valid",
  },
  REVOKED: {
    title: "Certificado revogado",
    seal: "revoked",
    text: "text-revoked",
    wash: "bg-revoked-wash",
    border: "border-revoked",
  },
  NOT_FOUND: {
    title: "Certificado não encontrado",
    seal: "not_found",
    text: "text-neutral",
    wash: "bg-neutral-wash",
    border: "border-neutral",
  },
  INVALID_TAMPERED: {
    title: "Documento adulterado",
    seal: "tampered",
    text: "text-danger",
    wash: "bg-danger-wash",
    border: "border-danger",
  },
  INVALID_SIGNATURE: {
    title: "Assinatura não reconhecida",
    seal: "invalid",
    text: "text-danger",
    wash: "bg-danger-wash",
    border: "border-danger",
  },
};
