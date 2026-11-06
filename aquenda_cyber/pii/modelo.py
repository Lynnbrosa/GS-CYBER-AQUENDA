"""O que o motor devolve: achados com categoria LGPD, confiança e trecho já mascarado."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Sensibilidade(str, Enum):
    """Classificação pela LGPD (Lei 13.709/2018)."""

    PESSOAL = "dado_pessoal"  # art. 5º, I: identifica ou torna identificável
    SENSIVEL = "dado_pessoal_sensivel"  # art. 5º, II: saúde, vida sexual, identidade de gênero...
    CREDENCIAL = "credencial"  # não é categoria da LGPD, mas abre a porta para todos os outros


PESO_SENSIBILIDADE = {Sensibilidade.PESSOAL: 2, Sensibilidade.SENSIVEL: 3, Sensibilidade.CREDENCIAL: 3}


@dataclass(frozen=True)
class Achado:
    regra: str  # id estável da regra, ex. "cpf"
    nome: str  # nome para gente, ex. "CPF"
    sensibilidade: Sensibilidade
    inicio: int  # posição no texto original
    fim: int
    mascarado: str  # o trecho com quase tudo escondido, seguro para log e para o LLM
    confianca: float  # 0 a 1
    motivo: str  # por que a regra disparou, em uma frase
    origem: str = ""  # arquivo:linha, campo JSON, rota...
    extras: dict = field(default_factory=dict)

    def como_dict(self) -> dict:
        d = asdict(self)
        d["sensibilidade"] = self.sensibilidade.value
        return d


def mascarar(valor: str, visiveis_fim: int = 2, simbolo: str = "•") -> str:
    """Esconde tudo menos os últimos caracteres alfanuméricos. "123.456.789-09" -> "•••.•••.•••-09"."""
    from .normalizacao import INVISIVEIS

    valor = "".join(c for c in valor if c not in INVISIVEIS)
    alfanum = [i for i, c in enumerate(valor) if c.isalnum()]
    manter = set(alfanum[-visiveis_fim:]) if visiveis_fim > 0 else set()
    return "".join(c if (not c.isalnum() or i in manter) else simbolo for i, c in enumerate(valor))


def mascarar_tudo(valor: str) -> str:
    return mascarar(valor, visiveis_fim=0)
