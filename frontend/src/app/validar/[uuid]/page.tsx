import type { Metadata } from "next";
import Link from "next/link";

import { CodeResult } from "@/components/CodeResult";

export const metadata: Metadata = {
  title: "Resultado da validação",
  robots: { index: false, follow: false },
};

interface PageProps {
  params: Promise<{ uuid: string }>;
}

export default async function ValidarPage({ params }: PageProps) {
  const { uuid } = await params;
  let code = uuid;
  try {
    code = decodeURIComponent(uuid);
  } catch {
    // Código malformado: o componente mostra a mensagem de formato inválido.
  }
  return (
    <div className="space-y-6">
      <CodeResult code={code} level={1} />
      <Link href="/" className="btn-quiet">
        Validar outro certificado
      </Link>
    </div>
  );
}
