"""Normalização contra evasão, sem perder a posição no texto original.

Quem quer vazar (ou esconder) um CPF escreve "１２３.４５６" em dígitos largos, enfia um
caractere invisível no meio ou troca a letra O pelo zero. O motor procura no texto
normalizado e devolve as posições do texto original, para mascarar o lugar certo.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Caracteres que não aparecem na tela e são usados para quebrar o reconhecimento.
INVISIVEIS = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "﻿",  # BOM
    "­",  # soft hyphen
}


@dataclass(frozen=True)
class TextoNormalizado:
    original: str
    normal: str
    # mapa[i] = posição no original do caractere normal[i]
    mapa: tuple[int, ...]

    def para_original(self, inicio: int, fim: int) -> tuple[int, int]:
        """Converte um intervalo [inicio, fim) do texto normal para o original."""
        if not self.mapa:
            return (0, 0)
        ini = self.mapa[min(inicio, len(self.mapa) - 1)]
        ultimo = self.mapa[min(fim - 1, len(self.mapa) - 1)]
        return (ini, ultimo + 1)


def normalizar(texto: str) -> TextoNormalizado:
    """NFKC por caractere (dígitos largos viram ASCII), remove invisíveis e guarda o mapa."""
    saida: list[str] = []
    mapa: list[int] = []
    for i, c in enumerate(texto):
        if c in INVISIVEIS:
            continue
        n = unicodedata.normalize("NFKC", c)
        for parte in n:
            saida.append(parte)
            mapa.append(i)
    return TextoNormalizado(texto, "".join(saida), tuple(mapa))


def sem_acento(texto: str) -> str:
    """Para comparar palavras de contexto: "Saúde" e "saude" contam igual."""
    decomposto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in decomposto if not unicodedata.combining(c)).lower()


def so_digitos(texto: str) -> str:
    return "".join(c for c in texto if c.isdigit())
