import type { ReactElement } from "react";

import type { SealState } from "@/lib/verdict";

interface SealProps {
  state: SealState;
  /** Tamanho em pixels (o selo é quadrado). */
  size?: number;
}

/** Selo de verificação: o mesmo desenho muda de glifo e cor conforme o veredito. */
export function Seal({ state, size = 132 }: SealProps) {
  const glyph = ((): ReactElement => {
    switch (state) {
      case "valid":
        return <path className="seal-draw" pathLength={100} d="M52 82l18 18 38-42" strokeWidth={9} />;
      case "revoked":
        return <path className="seal-draw" pathLength={100} d="M56 56v48M104 56v48" strokeWidth={9} />;
      case "not_found":
        return (
          <g strokeWidth={8}>
            <path className="seal-draw" pathLength={100} d="M62 66c0-10 8-16 18-16s18 6 18 15c0 12-18 14-18 28" />
            <path d="M80 110v.01" strokeWidth={11} />
          </g>
        );
      case "tampered":
      case "invalid":
        return <path className="seal-draw" pathLength={100} d="M58 58l44 44M102 58l-44 44" strokeWidth={9} />;
      case "loading":
        return <path d="M80 60v22l14 9" strokeWidth={7} />;
      case "idle":
        return <path d="M62 82l13 13 25-28" strokeWidth={7} opacity={0.35} />;
    }
  })();

  return (
    <svg
      viewBox="0 0 160 160"
      width={size}
      height={size}
      role="img"
      aria-hidden="true"
      focusable="false"
      className={state === "loading" || state === "idle" ? undefined : "seal-stamp"}
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={80} cy={80} r={74} strokeWidth={3} />
      <circle
        cx={80}
        cy={80}
        r={66}
        strokeWidth={5}
        strokeDasharray="2 5.2"
        className={state === "loading" ? "seal-spin" : undefined}
      />
      <circle cx={80} cy={80} r={54} strokeWidth={2} />
      {glyph}
    </svg>
  );
}
