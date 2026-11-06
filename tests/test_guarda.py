"""Bloqueio em tempo de execução: log redigido, resposta mascarada ou bloqueada."""

import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aquenda_cyber.guarda import FiltroPII, GuardaDeSaida, VazamentoBloqueado, saida_segura

CPF = "529.982.247-25"


def criar_api(**kw):
    app = FastAPI()

    @app.get("/vagas")
    def vagas():
        return {
            "itens": [
                {"titulo": "Atendente", "descricao": f"Mande currículo para rh.fulana@gmail.com ou CPF {CPF}", "telefone": "(11) 3333-4444"},
                {"titulo": "Recepção", "descricao": "Vaga afirmativa para pessoas trans"},
            ]
        }

    @app.get("/limpo")
    def limpo():
        return {"ok": True, "texto": "UBS República faz hormonização"}

    app.add_middleware(GuardaDeSaida, **kw)
    return TestClient(app)


def test_mascarar_tira_o_dado_e_mantem_o_resto():
    c = criar_api(permitidos=[r"\$\.itens\[\d+\]\.telefone"])
    r = c.get("/vagas")
    assert r.status_code == 200
    item = r.json()["itens"][0]
    assert CPF not in item["descricao"] and "rh.fulana@gmail.com" not in item["descricao"]
    assert "[CPF]" in item["descricao"] and "[E-MAIL]" in item["descricao"]
    assert item["telefone"] == "(11) 3333-4444"  # telefone público da vaga é permitido
    assert r.headers["x-aquenda-pii"] == "2"
    assert r.json()["itens"][1]["descricao"] == "Vaga afirmativa para pessoas trans"


def test_bloquear_devolve_problem_details():
    r = criar_api(modo="bloquear").get("/vagas")
    assert r.status_code == 502
    assert r.headers["content-type"].startswith("application/problem+json")
    assert set(r.json()["tipos"]) >= {"CPF", "E-mail"}
    assert CPF not in r.text


def test_resposta_sem_pii_passa_intacta():
    r = criar_api(modo="bloquear").get("/limpo")
    assert r.status_code == 200 and r.json()["texto"] == "UBS República faz hormonização"
    assert "x-aquenda-pii" not in r.headers


def test_filtro_de_log_redige_antes_de_gravar(caplog):
    lg = logging.getLogger("teste.aquenda")
    lg.addFilter(FiltroPII())
    with caplog.at_level(logging.INFO, logger="teste.aquenda"):
        lg.info("pedido de %s com senha: %s", CPF, "Lua2580!")
    texto = caplog.records[0].getMessage()
    assert CPF not in texto and "Lua2580!" not in texto
    assert "[CPF]" in texto and "[SENHA OU PIN]" in texto


def test_saida_segura_para_outras_saidas():
    assert saida_segura({"evento": "abriu_mapa"}, "analytics") == {"evento": "abriu_mapa"}
    with pytest.raises(VazamentoBloqueado) as e:
        saida_segura({"anotacao": "tomo 2 mg de estradiol"}, "analytics")
    assert "Dado de saúde" in str(e.value)
