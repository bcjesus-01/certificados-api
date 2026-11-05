/** Cliente da API de validação pública (contratos espelham app/schemas/validation.py). */

import { API_BASE_URL } from "./config";

export type ValidationStatus = "VALID" | "REVOKED" | "NOT_FOUND" | "INVALID_TAMPERED" | "INVALID_SIGNATURE";

export interface PublicCertificate {
  cert_uuid: string;
  recipient_name: string;
  recipient_doc: string | null;
  role: string;
  event_name: string;
  event_date: string | null;
  workload_hours: number | null;
  issued_at: string;
  file_sha256: string;
  signer_fingerprint: string | null;
  revoked: boolean;
  revoked_at: string | null;
}

export interface DownloadLink {
  url: string;
  expires_in_seconds: number;
  expires_at: string;
}

export interface CryptoReport {
  signature_count: number;
  intact: boolean | null;
  valid: boolean | null;
  trusted: boolean | null;
  covers_entire_file: boolean | null;
  hash_matches_record: boolean;
  signer_matches_record: boolean | null;
  signer_fingerprint: string | null;
  evaluated_at: string | null;
  summary: string | null;
  findings: string[];
}

interface BaseValidation {
  status: ValidationStatus;
  message: string;
  verified_at: string;
  certificate: PublicCertificate | null;
}

export interface CodeValidation extends BaseValidation {
  download: DownloadLink | null;
}

export interface FileValidation extends BaseValidation {
  file_sha256: string;
  file_size_bytes: number;
  crypto: CryptoReport;
}

export type ApiErrorKind = "network" | "unavailable" | "too_large" | "not_pdf" | "empty" | "unexpected";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;

  constructor(kind: ApiErrorKind, message: string) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
  }
}

const STATUSES: readonly string[] = ["VALID", "REVOKED", "NOT_FOUND", "INVALID_TAMPERED", "INVALID_SIGNATURE"];
const CODE_TIMEOUT_MS = 30_000;
const FILE_TIMEOUT_MS = 60_000;

const MESSAGES = {
  network: "Não foi possível falar com o servidor de validação. Confira sua conexão e tente de novo.",
  unavailable: "O serviço de validação está indisponível no momento. Tente novamente em instantes.",
  unexpected: "O servidor respondeu algo inesperado. Tente novamente; se persistir, avise a organização do evento.",
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasValidStatus(value: unknown): value is Record<string, unknown> & { status: ValidationStatus } {
  return isRecord(value) && typeof value.status === "string" && STATUSES.includes(value.status);
}

async function request(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new ApiError("network", MESSAGES.network);
  } finally {
    clearTimeout(timer);
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return (await response.json()) as unknown;
  } catch {
    throw new ApiError("unexpected", MESSAGES.unexpected);
  }
}

/** Consulta por código / QR Code. `404` com `status=NOT_FOUND` é um resultado, não um erro. */
export async function validateByCode(uuid: string): Promise<CodeValidation> {
  const response = await request(
    `${API_BASE_URL}/api/v1/validate/${encodeURIComponent(uuid)}`,
    { method: "GET", headers: { Accept: "application/json" } },
    CODE_TIMEOUT_MS,
  );
  if (response.status === 503) {
    throw new ApiError("unavailable", MESSAGES.unavailable);
  }
  const body = await readJson(response);
  if ((response.status === 200 || response.status === 404) && hasValidStatus(body)) {
    return body as unknown as CodeValidation;
  }
  throw new ApiError("unexpected", MESSAGES.unexpected);
}

/** Perícia de um PDF. O nome original do arquivo não é enviado (pode conter dados pessoais). */
export async function validateFile(file: File): Promise<FileValidation> {
  const form = new FormData();
  form.append("file", file, "certificado.pdf");
  const response = await request(
    `${API_BASE_URL}/api/v1/validate/file`,
    { method: "POST", body: form, headers: { Accept: "application/json" } },
    FILE_TIMEOUT_MS,
  );
  switch (response.status) {
    case 413:
      throw new ApiError("too_large", "O arquivo é maior do que o servidor aceita para validação.");
    case 415:
      throw new ApiError("not_pdf", "O arquivo enviado não é um PDF.");
    case 422:
      throw new ApiError("empty", "O arquivo está vazio ou não foi recebido. Escolha o PDF de novo.");
    case 503:
      throw new ApiError("unavailable", MESSAGES.unavailable);
    default:
      break;
  }
  const body = await readJson(response);
  if (response.status === 200 && hasValidStatus(body) && isRecord(body.crypto)) {
    return body as unknown as FileValidation;
  }
  throw new ApiError("unexpected", MESSAGES.unexpected);
}
