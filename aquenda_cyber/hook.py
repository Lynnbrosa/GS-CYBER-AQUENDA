"""Verificação no repositório: o pre-commit que barra segredo e dado pessoal antes do commit.

    python -m aquenda_cyber instalar-hook ../GS-c--AQUENDA     # instala em .git/hooks/pre-commit
    python -m aquenda_cyber verificar-commit                    # o que o hook roda (linhas adicionadas no stage)

O que barra:
- em qualquer arquivo: senha, token, chave de API e cartão (credenciais) com confiança alta;
- em arquivo de dados (json, csv, env, txt, sql, log, yaml): também CPF, CNS, nome de registro e dado de saúde.
Em código, só credencial conta: o código fala de "cpf" e "senha" o tempo todo sem ter dado de ninguém.

Para uma amostra de propósito (fixture, evidência), liste o caminho em .aquenda-pii-permitidos
(um padrão glob por linha) ou escreva "aquenda-pii: ok" na própria linha.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .pii import MotorPII, Sensibilidade

ARQUIVO_PERMITIDOS = ".aquenda-pii-permitidos"
MARCADOR_OK = "aquenda-pii: ok"
EXT_DADOS = {".json", ".csv", ".env", ".txt", ".sql", ".log", ".yaml", ".yml", ".tsv", ".xml", ".ini", ".properties"}
EXT_IGNORADAS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".db", ".dll", ".exe", ".ttf", ".woff", ".ico", ".lock"}
SEMPRE_PERMITIDOS = ["package-lock.json", "*/package-lock.json", "*.lock", "node_modules/*"]
REGRAS_EM_DADOS = {"cpf", "cns", "nome_registro", "saude", "cartao"}
TESTE = re.compile(r"(^|/)(tests?|__tests__|fixtures?)/|\.(test|spec)\.[jt]sx?$|Tests?\.cs$")


@dataclass
class Bloqueio:
    arquivo: str
    linha: int
    dado: str
    mascarado: str

    def __str__(self) -> str:
        return f"  {self.arquivo}:{self.linha}  {self.dado}: {self.mascarado}"


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout


def linhas_adicionadas(repo: Path) -> dict[str, list[tuple[int, str]]]:
    """Só o que entra neste commit: as linhas com + no diff do stage, com o número da linha no arquivo novo."""
    saida: dict[str, list[tuple[int, str]]] = {}
    arquivo, numero = None, 0
    for linha in _git("diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR", cwd=repo).splitlines():
        if linha.startswith("+++ "):
            arquivo = linha[6:] if linha.startswith("+++ b/") else None
        elif linha.startswith("@@"):
            m = re.search(r"\+(\d+)", linha)
            numero = int(m.group(1)) if m else 0
        elif arquivo and linha.startswith("+"):
            saida.setdefault(arquivo, []).append((numero, linha[1:]))
            numero += 1
    return saida


def permitidos(repo: Path) -> list[str]:
    arq = repo / ARQUIVO_PERMITIDOS
    extra = [l.strip() for l in arq.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")] if arq.exists() else []
    return SEMPRE_PERMITIDOS + extra


def _literal(texto: str, inicio: int) -> bool:
    return inicio > 0 and texto[inicio - 1] in "\"'`"


def verificar(repo: Path, motor: MotorPII | None = None) -> list[Bloqueio]:
    motor = motor or MotorPII()
    globs = permitidos(repo)
    bloqueios: list[Bloqueio] = []
    for arquivo, linhas in linhas_adicionadas(repo).items():
        ext = Path(arquivo).suffix.lower()
        if ext in EXT_IGNORADAS or any(fnmatch.fnmatch(arquivo, g) for g in globs):
            continue
        dados = ext in EXT_DADOS or Path(arquivo).name.startswith(".env")
        teste = bool(TESTE.search(arquivo))
        for numero, texto in linhas:
            if MARCADOR_OK in texto:
                continue
            for a in motor.encontrar(texto, f"{arquivo}:{numero}"):
                credencial = a.sensibilidade == Sensibilidade.CREDENCIAL and a.confianca >= 0.9
                if credencial and not dados and a.regra == "senha":
                    # em código, "senha" só conta com valor literal entre aspas, e não com uma chamada como lerSenha()
                    credencial = _literal(texto, a.inicio)
                pessoal = dados and not teste and a.regra in REGRAS_EM_DADOS
                if credencial or pessoal:
                    bloqueios.append(Bloqueio(arquivo, numero, a.nome, a.mascarado))
    return bloqueios


def cmd_verificar(repo: Path) -> int:
    bloqueios = verificar(repo)
    if not bloqueios:
        return 0
    print("Commit barrado pelo Aquenda: tem segredo ou dado pessoal nas linhas novas.", file=sys.stderr)
    for b in bloqueios:
        print(str(b), file=sys.stderr)
    print(f"\nTire o dado do arquivo. Se for amostra de propósito, liste o caminho em {ARQUIVO_PERMITIDOS} "
          f"ou marque a linha com '{MARCADOR_OK}'.", file=sys.stderr)
    return 1


def instalar(repo: Path) -> Path:
    git_dir = Path(_git("rev-parse", "--absolute-git-dir", cwd=repo).strip())
    hook = git_dir / "hooks" / "pre-commit"
    raiz_cyber = Path(__file__).resolve().parents[1]
    python = Path(sys.executable).as_posix()
    hook.write_text(
        "#!/bin/sh\n"
        "# Instalado por: python -m aquenda_cyber instalar-hook (GS-CYBER-AQUENDA)\n"
        "# Barra segredo e dado pessoal nas linhas novas do commit.\n"
        f'PYTHONPATH="{raiz_cyber.as_posix()}" PYTHONUTF8=1 exec "{python}" -m aquenda_cyber verificar-commit\n',
        encoding="utf-8", newline="\n",
    )
    hook.chmod(0o755)
    return hook
