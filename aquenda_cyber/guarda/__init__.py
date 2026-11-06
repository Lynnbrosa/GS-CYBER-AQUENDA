"""Bloqueio em tempo de execução: o dado sensível não sai por log nem por resposta de API.

- `FiltroPII`: filtro de logging que redige PII antes de gravar a linha.
- `GuardaDeSaida`: middleware ASGI (FastAPI/Starlette) que inspeciona cada resposta JSON e
  mascara ou bloqueia o dado pessoal antes de ele sair.
- `saida_segura`: para qualquer outra saída (arquivo, fila, webhook): levanta se houver PII.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable

from ..pii import MotorPII
from ..pii.modelo import Achado, Sensibilidade

_motor = MotorPII()


class VazamentoBloqueado(Exception):
    def __init__(self, destino: str, achados: list[Achado]):
        self.destino = destino
        self.achados = achados
        tipos = ", ".join(sorted({a.nome for a in achados}))
        super().__init__(f"Saída para {destino} bloqueada: contém {tipos}.")


def saida_segura(valor: object, destino: str, motor: MotorPII = _motor) -> object:
    """Devolve o valor se ele não tiver PII; senão levanta VazamentoBloqueado."""
    achados = motor.varrer_estrutura(valor) if not isinstance(valor, str) else motor.encontrar(valor)
    if achados:
        raise VazamentoBloqueado(destino, achados)
    return valor


# ---------------------------------------------------------------- logs


class FiltroPII(logging.Filter):
    """Redige PII da mensagem e dos argumentos. Nunca descarta a linha: só esconde o dado."""

    def __init__(self, motor: MotorPII = _motor):
        super().__init__()
        self.motor = motor

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            mensagem = record.getMessage()
        except Exception:  # noqa: BLE001 - log mal formatado não pode derrubar a aplicação
            return True
        redigida = self.motor.redigir(mensagem)
        if redigida != mensagem:
            record.msg = redigida
            record.args = ()
            record.pii_redigida = True
        return True


def instalar_filtro(loggers: Iterable[str] = ("", "uvicorn", "uvicorn.access", "uvicorn.error", "httpx")) -> FiltroPII:
    filtro = FiltroPII()
    for nome in loggers:
        lg = logging.getLogger(nome)
        lg.addFilter(filtro)
        for h in lg.handlers:
            h.addFilter(filtro)
    return filtro


# ---------------------------------------------------------------- respostas HTTP


class GuardaDeSaida:
    """Middleware ASGI. `modo="mascarar"` troca o dado por um rótulo; `modo="bloquear"` devolve 502.

    `permitidos` são caminhos JSON (regex) que podem levar o dado de propósito, por exemplo o
    telefone público de uma unidade de saúde: r"\\$\\.itens\\[\\d+\\]\\.telefone".
    """

    def __init__(self, app, modo: str = "mascarar", permitidos: Iterable[str] = (), sensibilidade_minima: Sensibilidade | None = None, motor: MotorPII = _motor):
        self.app = app
        self.modo = modo
        self.permitidos = [re.compile(p) for p in permitidos]
        self.motor = motor
        self.sensibilidade_minima = sensibilidade_minima

    def _permitido(self, origem: str) -> bool:
        return any(p.fullmatch(origem) for p in self.permitidos)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        inicio: dict = {}
        corpo = bytearray()

        async def capturar(msg):
            if msg["type"] == "http.response.start":
                inicio.update(msg)
                return
            if msg["type"] == "http.response.body":
                corpo.extend(msg.get("body", b""))
                if msg.get("more_body"):
                    return
                await self._enviar(inicio, bytes(corpo), send)

        await self.app(scope, receive, capturar)

    async def _enviar(self, inicio: dict, corpo: bytes, send) -> None:
        cabecalhos = [(k, v) for k, v in inicio.get("headers", []) if k.lower() != b"content-length"]
        tipo = dict(inicio.get("headers", [])).get(b"content-type", b"")
        achados: list[Achado] = []
        if b"json" in tipo and corpo:
            try:
                dado = json.loads(corpo)
            except ValueError:
                dado = None
            if dado is not None:
                achados = [a for a in self.motor.varrer_estrutura(dado) if not self._permitido(a.origem)]
                if achados and self.modo == "bloquear":
                    problema = {
                        "type": "about:blank",
                        "title": "Resposta bloqueada",
                        "status": 502,
                        "detail": "A resposta tinha dado pessoal e não saiu do servidor.",
                        "tipos": sorted({a.nome for a in achados}),
                    }
                    corpo = json.dumps(problema, ensure_ascii=False).encode()
                    inicio = {**inicio, "status": 502}
                    cabecalhos = [(k, v) for k, v in cabecalhos if k.lower() != b"content-type"] + [(b"content-type", b"application/problem+json")]
                elif achados:
                    corpo = json.dumps(_mascarar(dado, self.motor, self._permitido), ensure_ascii=False).encode()
        cabecalhos.append((b"content-length", str(len(corpo)).encode()))
        if achados:
            cabecalhos.append((b"x-aquenda-pii", str(len(achados)).encode()))
        await send({"type": "http.response.start", "status": inicio.get("status", 200), "headers": cabecalhos})
        await send({"type": "http.response.body", "body": corpo})


def _mascarar(dado, motor: MotorPII, permitido, caminho: str = "$"):
    if isinstance(dado, dict):
        saida = {}
        for k, v in dado.items():
            filho = f"{caminho}.{k}"
            achados = motor.varrer_estrutura({k: v}, caminho) if not isinstance(v, (dict, list)) else []
            if achados and not any(permitido(a.origem) for a in achados) and any(a.origem == filho and a.inicio == 0 and a.fim == len(str(v)) and a.regra == _chave(k) for a in achados):
                saida[k] = "[DADO PROTEGIDO]"
            else:
                saida[k] = _mascarar(v, motor, permitido, filho)
        return saida
    if isinstance(dado, list):
        return [_mascarar(v, motor, permitido, f"{caminho}[{i}]") for i, v in enumerate(dado)]
    if isinstance(dado, str) and not permitido(caminho):
        return motor.redigir(dado)
    return dado


def _chave(k: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", k.lower()).strip("_")
