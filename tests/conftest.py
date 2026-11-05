"""Configuração comum dos testes: torna o pacote ``app`` e ``scripts`` importáveis.

Os testes não precisam de segredos, banco, bucket nem rede: usam fakes e certificados
efêmeros gerados em memória.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
