"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { extractUuid } from "@/lib/format";

export function CodeForm() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const uuid = extractUuid(value);
    if (!uuid) {
      setError("Informe o código do certificado (UUID) ou cole o endereço lido no QR Code.");
      return;
    }
    setError(null);
    router.push(`/validar/${uuid}`);
  };

  return (
    <form onSubmit={submit} noValidate className="space-y-4">
      <div>
        <label htmlFor="codigo" className="block text-sm font-medium">
          Código do certificado
        </label>
        <p id="codigo-ajuda" className="mt-1 text-sm text-ink-soft">
          Está impresso no certificado, abaixo do QR Code. Você também pode colar o endereço do QR Code.
        </p>
        <input
          id="codigo"
          name="codigo"
          type="text"
          inputMode="text"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          aria-describedby={error ? "codigo-ajuda codigo-erro" : "codigo-ajuda"}
          aria-invalid={error ? true : undefined}
          placeholder="00000000-0000-4000-8000-000000000000"
          className="field-input mt-3"
        />
        {error ? (
          <p id="codigo-erro" role="alert" className="mt-2 text-sm font-medium text-danger">
            {error}
          </p>
        ) : null}
      </div>
      <button type="submit" className="btn-primary">
        Validar certificado
      </button>
    </form>
  );
}
