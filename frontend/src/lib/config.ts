/** Configuração pública do portal (variáveis NEXT_PUBLIC_* são embutidas no build). */

const DEFAULT_MAX_UPLOAD_BYTES = 1_000_000;

export const API_BASE_URL: string = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000").replace(
  /\/+$/,
  "",
);

const parsedMaxUpload = Number(process.env.NEXT_PUBLIC_MAX_UPLOAD_BYTES);
export const MAX_UPLOAD_BYTES: number =
  Number.isFinite(parsedMaxUpload) && parsedMaxUpload > 0 ? parsedMaxUpload : DEFAULT_MAX_UPLOAD_BYTES;

export const ORG_NAME: string = process.env.NEXT_PUBLIC_ORG_NAME?.trim() || "CACIC UESC";
