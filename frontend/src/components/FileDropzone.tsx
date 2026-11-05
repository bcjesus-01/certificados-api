"use client";

import { useRef, useState, type ChangeEvent, type DragEvent } from "react";

import { MAX_UPLOAD_BYTES } from "@/lib/config";
import { formatBytes } from "@/lib/format";

interface FileDropzoneProps {
  disabled: boolean;
  onFile: (file: File) => void;
}

function problemWith(file: File): string | null {
  if (file.size === 0) return "O arquivo está vazio.";
  const looksLikePdf = file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf");
  if (!looksLikePdf) return "Envie um arquivo PDF.";
  if (file.size > MAX_UPLOAD_BYTES) {
    return `O PDF tem ${formatBytes(file.size)}; o limite para perícia é ${formatBytes(MAX_UPLOAD_BYTES)}.`;
  }
  return null;
}

export function FileDropzone({ disabled, onFile }: FileDropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const accept = (file: File | undefined): void => {
    if (!file) return;
    const found = problemWith(file);
    setProblem(found);
    if (!found) onFile(file);
  };

  const onChange = (event: ChangeEvent<HTMLInputElement>): void => {
    accept(event.target.files?.[0]);
    // Permite escolher o mesmo arquivo de novo.
    event.target.value = "";
  };

  const onDrop = (event: DragEvent<HTMLLabelElement>): void => {
    event.preventDefault();
    setDragging(false);
    if (disabled) return;
    accept(event.dataTransfer.files[0]);
  };

  return (
    <div>
      <label
        htmlFor="arquivo-pdf"
        onDragOver={(event) => {
          event.preventDefault();
          if (!disabled) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex min-h-[200px] cursor-pointer flex-col items-center justify-center gap-2 border-2 border-dashed p-6 text-center transition-colors focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-ink ${
          dragging ? "border-ink bg-neutral-wash" : "border-rule bg-paper"
        } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
      >
        <input
          ref={inputRef}
          id="arquivo-pdf"
          type="file"
          accept="application/pdf,.pdf"
          className="sr-only"
          disabled={disabled}
          onChange={onChange}
        />
        <span className="font-display text-xl font-semibold">Solte o PDF do certificado aqui</span>
        <span className="text-sm text-ink-soft">ou clique para escolher o arquivo (até {formatBytes(MAX_UPLOAD_BYTES)})</span>
      </label>
      {problem ? (
        <p role="alert" className="mt-2 text-sm font-medium text-danger">
          {problem}
        </p>
      ) : null}
    </div>
  );
}
