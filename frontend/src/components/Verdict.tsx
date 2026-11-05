"use client";

import { useEffect, useRef } from "react";

import { VERDICTS } from "@/lib/verdict";
import type { ValidationStatus } from "@/lib/api";

import { Seal } from "./Seal";

interface VerdictProps {
  status: ValidationStatus;
  message: string;
  /** Nível do título: h1 na página dedicada, h2 quando aparece dentro da Home. */
  level: 1 | 2;
}

export function Verdict({ status, message, level }: VerdictProps) {
  const style = VERDICTS[status];
  const headingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    // Leitores de tela anunciam o resultado assim que ele aparece.
    headingRef.current?.focus();
  }, [status]);

  const heading =
    level === 1 ? (
      <h1 ref={headingRef} tabIndex={-1} className="font-display text-3xl font-semibold tracking-tight outline-none">
        {style.title}
      </h1>
    ) : (
      <h2 ref={headingRef} tabIndex={-1} className="font-display text-3xl font-semibold tracking-tight outline-none">
        {style.title}
      </h2>
    );

  return (
    <div className={`flex flex-col items-start gap-5 border-l-4 p-5 sm:flex-row sm:items-center ${style.wash} ${style.border}`}>
      <div className={`shrink-0 ${style.text}`}>
        <Seal state={style.seal} />
      </div>
      <div className="min-w-0">
        <div className={style.text}>{heading}</div>
        <p className="mt-2 max-w-reading text-sm leading-relaxed text-ink">{message}</p>
      </div>
    </div>
  );
}
