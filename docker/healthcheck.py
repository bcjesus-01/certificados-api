"""HEALTHCHECK da imagem: consulta /healthz (liveness) na porta do contêiner.

Usa só a biblioteca padrão (a imagem slim não tem curl). Não toca o banco nem o storage:
reiniciar o contêiner por uma falha transitória do Supabase só pioraria a indisponibilidade.
A prontidão (banco + storage) fica em /readyz, para o balanceador.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    port = os.environ.get("PORT", "8080")
    url = f"http://127.0.0.1:{port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=4) as response:  # noqa: S310 - URL fixa em loopback
            return 0 if response.status == 200 else 1
    except (urllib.error.URLError, OSError, ValueError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
