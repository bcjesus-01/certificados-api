import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import { ORG_NAME } from "@/lib/config";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Validação de certificados", template: "%s · Validação de certificados" },
  description: `Confira a autenticidade de um certificado emitido por ${ORG_NAME}: por código ou QR Code, ou enviando o PDF para perícia da assinatura digital.`,
  referrer: "no-referrer",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="pt-BR">
      <body className="flex min-h-screen flex-col">
        <a
          href="#conteudo"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:bg-paper focus:px-3 focus:py-2"
        >
          Ir para o conteúdo
        </a>
        <header className="border-b border-rule bg-paper/80 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-baseline justify-between gap-4 px-4 py-4 sm:px-6">
            <p className="font-display text-lg font-semibold tracking-tight">{ORG_NAME}</p>
            <p className="text-sm text-ink-soft">Validação de certificados</p>
          </div>
        </header>
        <main id="conteudo" className="mx-auto w-full max-w-5xl flex-1 px-4 py-8 sm:px-6 sm:py-12">
          {children}
        </main>
        <footer className="border-t border-rule">
          <p className="mx-auto max-w-5xl px-4 py-5 text-xs leading-relaxed text-ink-soft sm:px-6">
            Os arquivos enviados para perícia são analisados na memória do servidor e descartados em seguida. Documentos
            de identificação são exibidos sempre mascarados, conforme a LGPD.
          </p>
        </footer>
      </body>
    </html>
  );
}
