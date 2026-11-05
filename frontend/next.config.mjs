// @ts-check
const isProduction = process.env.NODE_ENV === "production";
const rawApiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL;

if (isProduction && !rawApiBaseUrl) {
  throw new Error(
    "NEXT_PUBLIC_API_BASE_URL é obrigatória no build de produção (ex.: https://api.seudominio.com.br).",
  );
}

/** Origem da API: única origem externa liberada para fetch/XHR na CSP. */
const apiOrigin = (() => {
  try {
    return new URL(rawApiBaseUrl ?? "http://localhost:8000").origin;
  } catch {
    throw new Error("NEXT_PUBLIC_API_BASE_URL não é uma URL válida.");
  }
})();

// O Next injeta scripts/estilos inline na hidratação, então 'unsafe-inline' é necessário sem nonces.
// Em desenvolvimento o React Refresh também exige 'unsafe-eval' e WebSocket local.
const contentSecurityPolicy = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isProduction ? "" : " 'unsafe-eval'"}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' ${apiOrigin}${isProduction ? "" : " ws://localhost:* http://localhost:*"}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: contentSecurityPolicy },
          // A URL de validação contém o código do certificado: nunca vazar via Referer.
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
        ],
      },
      {
        // Páginas por código não devem ser indexadas por buscadores.
        source: "/validar/:path*",
        headers: [{ key: "X-Robots-Tag", value: "noindex, nofollow" }],
      },
    ];
  },
};

export default nextConfig;
