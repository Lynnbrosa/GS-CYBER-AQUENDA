"""Motor de parsing de PII: roda as regras, resolve sobreposições, redige e varre fontes."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from pathlib import Path

from .modelo import Achado, Sensibilidade, mascarar_tudo
from .normalizacao import normalizar, sem_acento
from .regras import TODAS, Regra

# Nome de campo que, por si só, já diz que o valor é sensível.
CAMPOS_SENSIVEIS: dict[str, tuple[str, Sensibilidade]] = {
    "cpf": ("CPF", Sensibilidade.PESSOAL),
    "rg": ("RG", Sensibilidade.PESSOAL),
    "cns": ("Cartão SUS", Sensibilidade.SENSIVEL),
    "cartao_sus": ("Cartão SUS", Sensibilidade.SENSIVEL),
    "senha": ("Senha", Sensibilidade.CREDENCIAL),
    "password": ("Senha", Sensibilidade.CREDENCIAL),
    "pin": ("PIN", Sensibilidade.CREDENCIAL),
    "token": ("Token", Sensibilidade.CREDENCIAL),
    "nome_registro": ("Nome de registro", Sensibilidade.SENSIVEL),
    "nome_civil": ("Nome de registro", Sensibilidade.SENSIVEL),
    "diagnostico": ("Diagnóstico", Sensibilidade.SENSIVEL),
    "dose": ("Dose de medicamento", Sensibilidade.SENSIVEL),
    "medicamento": ("Medicamento", Sensibilidade.SENSIVEL),
}

# Campos que nunca guardam dado de pessoa (ou que guardam só o hash).
CAMPOS_IGNORADOS = re.compile(r"(hash|_id$|^id$|slug|codigo_cnes|codigo_ibge|fonte|url|link|cep_servico)", re.IGNORECASE)


def _chave_normal(chave: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", sem_acento(chave)).strip("_")


class MotorPII:
    def __init__(self, regras: Iterable[Regra] = TODAS, limiar: float = 0.5):
        self.regras = tuple(regras)
        self.limiar = limiar

    # ------------------------------------------------------------ texto

    def encontrar(self, texto: str, origem: str = "") -> list[Achado]:
        if not texto:
            return []
        tn = normalizar(texto)
        todos: list[Achado] = []
        for regra in self.regras:
            todos.extend(a for a in regra.encontrar(tn) if a.confianca >= self.limiar)
        # sobreposição: fica o mais confiável (e o maior, em empate). Um CPF não vira também telefone.
        todos.sort(key=lambda a: (-a.confianca, -(a.fim - a.inicio), a.inicio))
        escolhidos: list[Achado] = []
        for a in todos:
            if all(a.fim <= b.inicio or a.inicio >= b.fim for b in escolhidos):
                escolhidos.append(a)
        escolhidos.sort(key=lambda a: a.inicio)
        if origem:
            escolhidos = [_com_origem(a, origem) for a in escolhidos]
        return escolhidos

    def redigir(self, texto: str) -> str:
        """Troca cada dado encontrado por um rótulo: "CPF 123.456.789-09" -> "CPF [CPF]"."""
        saida = texto
        for a in sorted(self.encontrar(texto), key=lambda a: a.inicio, reverse=True):
            saida = saida[: a.inicio] + f"[{a.nome.upper()}]" + saida[a.fim :]
        return saida

    def tem_pii(self, texto: str) -> bool:
        return bool(self.encontrar(texto))

    # ------------------------------------------------------------ estruturas

    def varrer_estrutura(self, dado: object, caminho: str = "$") -> list[Achado]:
        """Percorre JSON (dict/list) e acha PII no valor ou pelo nome do campo."""
        achados: list[Achado] = []
        if isinstance(dado, dict):
            for k, v in dado.items():
                filho = f"{caminho}.{k}"
                chave = _chave_normal(str(k))
                if CAMPOS_IGNORADOS.search(chave):
                    continue
                if chave in CAMPOS_SENSIVEIS and isinstance(v, (str, int)) and str(v).strip():
                    nome, sens = CAMPOS_SENSIVEIS[chave]
                    achados.append(
                        Achado(chave, nome, sens, 0, len(str(v)), mascarar_tudo(str(v)), 0.9,
                               f"Campo chamado '{k}' com valor preenchido.", origem=filho)
                    )
                    continue
                achados.extend(self.varrer_estrutura(v, filho))
        elif isinstance(dado, list):
            for i, v in enumerate(dado):
                achados.extend(self.varrer_estrutura(v, f"{caminho}[{i}]"))
        elif isinstance(dado, str):
            achados.extend(self.encontrar(dado, caminho))
        return achados

    # ------------------------------------------------------------ fontes

    def varrer_arquivo(self, caminho: Path) -> list[Achado]:
        try:
            texto = caminho.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            return []
        if caminho.suffix.lower() == ".json":
            try:
                return self.varrer_estrutura(json.loads(texto), f"{caminho.name}:$")
            except json.JSONDecodeError:
                pass
        achados = []
        for n, linha in enumerate(texto.splitlines(), start=1):
            achados.extend(self.encontrar(linha, f"{caminho.as_posix()}:{n}"))
        return achados

    def varrer_pasta(self, pasta: Path, extensoes: tuple[str, ...] = (".json", ".log", ".txt", ".csv", ".md")) -> list[Achado]:
        achados = []
        for arq in sorted(pasta.rglob("*")):
            if arq.is_file() and arq.suffix.lower() in extensoes and "node_modules" not in arq.parts:
                achados.extend(self.varrer_arquivo(arq))
        return achados

    def varrer_sqlite(self, banco: Path, limite_por_tabela: int = 5000) -> list[Achado]:
        """Lê cada coluna de texto de cada tabela. Abre só para leitura."""
        achados: list[Achado] = []
        con = sqlite3.connect(f"file:{banco.as_posix()}?mode=ro", uri=True)
        try:
            tabelas = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for t in tabelas:
                colunas = [r[1] for r in con.execute(f'PRAGMA table_info("{t}")')]
                for linha_n, linha in enumerate(con.execute(f'SELECT * FROM "{t}" LIMIT {int(limite_por_tabela)}')):
                    for col, valor in zip(colunas, linha):
                        if not isinstance(valor, str) or CAMPOS_IGNORADOS.search(_chave_normal(col)):
                            continue
                        achados.extend(self.encontrar(valor, f"{banco.name}:{t}.{col}#{linha_n + 1}"))
        finally:
            con.close()
        return achados


def _com_origem(a: Achado, origem: str) -> Achado:
    from dataclasses import replace

    return replace(a, origem=origem)


def resumir(achados: Iterable[Achado]) -> dict[str, int]:
    contagem: dict[str, int] = {}
    for a in achados:
        contagem[a.regra] = contagem.get(a.regra, 0) + 1
    return dict(sorted(contagem.items(), key=lambda kv: -kv[1]))


def iterar_linhas(achados: Iterable[Achado]) -> Iterator[str]:
    for a in achados:
        yield f"{a.origem or '-'}  {a.nome}: {a.mascarado}  ({a.confianca:.0%}) {a.motivo}"
