"""Ponte Python para o analisador de taint em Node (taint_ts/analisar.mjs)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
ANALISADOR = RAIZ / "taint_ts" / "analisar.mjs"
POLITICA = RAIZ / "taint_ts" / "politica.json"


class TaintIndisponivel(RuntimeError):
    pass


def analisar_app(pasta_app: Path, politica: Path = POLITICA, tempo_limite: int = 300) -> dict:
    """Roda o analisador e devolve o relatório (fontes, fluxos, resumo)."""
    node = shutil.which("node")
    if not node:
        raise TaintIndisponivel("Node.js não encontrado: instale o Node 20+ para rodar o taint analysis.")
    if not (RAIZ / "node_modules" / "typescript").exists():
        raise TaintIndisponivel("Rode 'npm install' na pasta do GS-CYBER-AQUENDA (precisa do typescript).")
    proc = subprocess.run(
        [node, str(ANALISADOR), str(pasta_app), "--politica", str(politica)],
        capture_output=True, text=True, encoding="utf-8", timeout=tempo_limite, cwd=RAIZ,
    )
    if proc.returncode not in (0, 2):  # 2 = achou violação, não é erro
        raise TaintIndisponivel(f"O analisador falhou: {proc.stderr.strip()[:500]}")
    return json.loads(proc.stdout)
