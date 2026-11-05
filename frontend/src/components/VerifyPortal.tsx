"use client";

import { useState } from "react";

import { CodeForm } from "./CodeForm";
import { FileVerifier } from "./FileVerifier";

type Mode = "code" | "file";

const TABS: ReadonlyArray<{ mode: Mode; label: string }> = [
  { mode: "code", label: "Pelo código" },
  { mode: "file", label: "Pelo arquivo PDF" },
];

export function VerifyPortal() {
  const [mode, setMode] = useState<Mode>("code");

  return (
    <div className="grid gap-8 lg:grid-cols-[minmax(0,22rem)_1fr] lg:gap-12">
      <div>
        <h1 className="font-display text-4xl font-semibold leading-tight tracking-tight">
          Esse certificado é autêntico?
        </h1>
        <p className="mt-3 max-w-reading text-base leading-relaxed text-ink-soft">
          Confira pelo código do QR Code ou envie o PDF para examinar a assinatura digital.
        </p>
      </div>

      <div className="border border-rule bg-paper">
        <div role="tablist" aria-label="Forma de validação" className="flex border-b border-rule">
          {TABS.map((tab) => {
            const selected = tab.mode === mode;
            return (
              <button
                key={tab.mode}
                type="button"
                role="tab"
                id={`aba-${tab.mode}`}
                aria-selected={selected}
                aria-controls={`painel-${tab.mode}`}
                tabIndex={selected ? 0 : -1}
                onClick={() => setMode(tab.mode)}
                onKeyDown={(event) => {
                  if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
                    setMode(mode === "code" ? "file" : "code");
                  }
                }}
                className={`focus-ring min-h-[48px] flex-1 px-4 text-sm font-semibold transition-colors ${
                  selected ? "border-b-2 border-ink bg-paper" : "bg-neutral-wash text-ink-soft hover:text-ink"
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>
        <div
          role="tabpanel"
          id={`painel-${mode}`}
          aria-labelledby={`aba-${mode}`}
          className="p-5 sm:p-6"
        >
          {mode === "code" ? <CodeForm /> : <FileVerifier />}
        </div>
      </div>
    </div>
  );
}
