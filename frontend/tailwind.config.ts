import type { Config } from "tailwindcss";

/** Cores vêm de variáveis CSS (globals.css), o que dá o tema escuro sem classes `dark:`. */
const token = (name: string): string => `rgb(var(--${name}) / <alpha-value>)`;

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        field: token("field"),
        paper: token("paper"),
        ink: token("ink"),
        "ink-soft": token("ink-soft"),
        rule: token("rule"),
        valid: token("valid"),
        "valid-wash": token("valid-wash"),
        revoked: token("revoked"),
        "revoked-wash": token("revoked-wash"),
        danger: token("danger"),
        "danger-wash": token("danger-wash"),
        neutral: token("neutral"),
        "neutral-wash": token("neutral-wash"),
      },
      fontFamily: {
        display: ['"Iowan Old Style"', '"Palatino Linotype"', "Palatino", '"Book Antiqua"', "Georgia", "serif"],
        sans: ["ui-sans-serif", "system-ui", "-apple-system", '"Segoe UI"', "Roboto", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      maxWidth: { reading: "62ch" },
    },
  },
  plugins: [],
};

export default config;
