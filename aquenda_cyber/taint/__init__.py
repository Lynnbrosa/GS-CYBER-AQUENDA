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


# ---------------------------------------------------------------- Semgrep (regras de taint para C# e TS)

REGRAS = RAIZ / "rules"
REGRAS_CSHARP = REGRAS / "aquenda-csharp.yaml"
REGRAS_TS = REGRAS / "aquenda-typescript.yaml"


def _semgrep() -> str | None:
    import sys

    local = Path(sys.executable).with_name("semgrep.exe" if sys.platform == "win32" else "semgrep")
    return str(local) if local.exists() else shutil.which("semgrep")


def rodar_semgrep(alvo: Path, regras: Path, tempo_limite: int = 600) -> list[dict]:
    """Roda as regras do Aquenda no alvo e devolve os achados com a linha do código já lida."""
    exe = _semgrep()
    if not exe:
        raise TaintIndisponivel("Semgrep não encontrado: pip install semgrep.")
    import os

    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [exe, "--config", str(regras), str(alvo), "--json", "--metrics=off", "--quiet", "--disable-version-check"],
        capture_output=True, text=True, encoding="utf-8", timeout=tempo_limite, env=env,
    )
    if proc.returncode not in (0, 1):  # 1 = achou algo
        raise TaintIndisponivel(f"O Semgrep falhou: {proc.stderr.strip()[:500]}")
    dados = json.loads(proc.stdout)
    achados = []
    for r in dados["results"]:
        caminho = Path(r["path"])
        try:
            linha = caminho.read_text(encoding="utf-8").splitlines()[r["start"]["line"] - 1].strip()
        except (OSError, IndexError):
            linha = ""
        try:
            relativo = caminho.resolve().relative_to(Path(alvo).resolve()).as_posix()
        except ValueError:
            relativo = caminho.as_posix()
        achados.append({"regra": r["check_id"].rsplit(".", 1)[-1], "arquivo": relativo, "linha": r["start"]["line"],
                        "codigo": linha, "mensagem": " ".join(r["extra"]["message"].split()),
                        "metadata": r["extra"].get("metadata", {})})
    return achados
