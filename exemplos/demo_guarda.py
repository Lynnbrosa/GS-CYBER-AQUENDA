"""Demonstração das travas em tempo de execução: a mesma rota vazando, com e sem a guarda.

    python exemplos/demo_guarda.py
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from aquenda_cyber.guarda import GuardaDeSaida, VazamentoBloqueado, instalar_filtro, saida_segura

MENSAGENS = [
    {"id": 1, "autor": "kiwi-azul", "texto": "Comecei estradiol 2mg semana passada, alguém sentiu enjoo?"},
    {"id": 2, "autor": "elefante-roxo", "texto": "Meu CPF é 529.982.247-25, alguém sabe se o ambulatório pede?"},
    {"id": 3, "autor": "kiwi-azul", "texto": "Boa noite, gente!"},
]


def api() -> FastAPI:
    app = FastAPI()

    @app.get("/api/chat/salas/1/mensagens")
    def mensagens():
        return MENSAGENS

    return app


def mostrar(titulo: str, cliente: TestClient) -> None:
    r = cliente.get("/api/chat/salas/1/mensagens")
    print(f"\n== {titulo}: HTTP {r.status_code}  x-aquenda-pii={r.headers.get('x-aquenda-pii', '-')}")
    print(r.text)


print("1) Rota sem guarda: devolve tudo como está")
mostrar("sem guarda", TestClient(api()))

print("\n2) GuardaDeSaida(modo='mascarar'): o dado sensível sai mascarado")
mostrar("mascarar", TestClient(GuardaDeSaida(api(), modo="mascarar")))

print("\n3) GuardaDeSaida(modo='bloquear'): a resposta inteira é barrada")
mostrar("bloquear", TestClient(GuardaDeSaida(api(), modo="bloquear")))

print("\n4) saida_segura() antes de mandar para um destino inseguro")
try:
    saida_segura({"lembrete": "Testosterona 250mg, quinta 8h"}, destino="analytics")
except VazamentoBloqueado as e:
    print("VazamentoBloqueado:", e)

print("\n5) FiltroPII no logging: o log grava a versão mascarada")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout, force=True)
instalar_filtro()
logging.getLogger("aquenda").info("Login de 529.982.247-25 com Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcDEF123456ghiJKL")
