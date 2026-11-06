"""Eficácia do taint analysis: pega cada vazamento plantado, não aponta os casos limpos,
e prova que o app de verdade não deixa a agenda sair do celular (com teste de mutação)."""

import os
import shutil
from pathlib import Path

import pytest

from aquenda_cyber.taint import RAIZ, analisar_app

EXEMPLO = RAIZ / "taint_ts" / "exemplos" / "vulneravel"
APP = Path(os.environ.get("AQUENDA_APP", RAIZ.parent / "GS-MOBILE-AQUENDA"))

precisa_node = pytest.mark.skipif(not shutil.which("node"), reason="Node.js não instalado")


@pytest.fixture(scope="module")
def exemplo():
    return analisar_app(EXEMPLO)


def violacoes(rel):
    return {(f["rotulo"], f["sumidouro"], f["onde"]) for f in rel["fluxos"] if f["veredito"] == "violacao"}


@precisa_node
@pytest.mark.parametrize(
    "esperado",
    [
        ("agenda", "rede", "src/vazamentos.ts:10"),  # V1 direto
        ("agenda", "rede", "src/util.ts:6"),  # V2 por utilitário em outro arquivo e .map
        ("consultas", "link_externo", "src/vazamentos.ts:22"),  # V3 link do WhatsApp
        ("agenda", "log", "src/vazamentos.ts:28"),  # V4 console.log
        ("agenda", "armazenamento_sem_cifra", "src/vazamentos.ts:34"),  # V5 AsyncStorage
        ("pin", "log", "src/vazamentos.ts:39"),  # V6 PIN no log
        ("agenda", "rede", "src/app/agenda/formulario.tsx:8"),  # V7 estado do formulário
        ("localizacao", "rede", "src/posicao.ts:8"),  # V8 posição crua
        ("localizacao", "rede", "src/posicao.ts:21"),  # V9 campo sensível do objeto
    ],
)
def test_pega_cada_vazamento_plantado(exemplo, esperado):
    assert esperado in violacoes(exemplo)


@precisa_node
def test_nao_aponta_os_casos_limpos(exemplo):
    linhas_limpas = {
        "src/vazamentos.ts:45",  # OK1 só o hash do PIN
        "src/vazamentos.ts:50",  # OK2 utilitário compartilhado com texto público
        "src/vazamentos.ts:56",  # OK3 só id e contagem
        "src/posicao.ts:28",  # OK5 só o campo público
    }
    assert not {onde for _, _, onde in violacoes(exemplo)} & linhas_limpas
    # OK4: posição arredondada sai, mas como permitida
    permitidos = {f["onde"] for f in exemplo["fluxos"] if f["veredito"] == "permitido"}
    assert "src/posicao.ts:14" in permitidos
    assert exemplo["resumo"]["violacoes"] == 9


@precisa_node
def test_trilha_mostra_o_caminho_entre_arquivos(exemplo):
    v2 = next(f for f in exemplo["fluxos"] if f["onde"] == "src/util.ts:6")
    texto = " ".join(v2["trilha"])
    assert "fonte" in v2["trilha"][0]
    assert "resumoDoDia" in texto and "enviar" in texto


@precisa_node
@pytest.mark.skipif(not (APP / "src").exists(), reason="app GS-MOBILE-AQUENDA não está ao lado")
def test_app_real_nao_deixa_agenda_consulta_nem_pin_sairem():
    rel = analisar_app(APP)
    assert rel["arquivos_analisados"] > 40
    assert rel["resumo"]["violacoes"] == 0
    rotulos_na_rede = {f["rotulo"] for f in rel["fluxos"] if f["sumidouro"] == "rede"}
    assert not {"agenda", "consultas", "pin"} & rotulos_na_rede
    # a posição só sai arredondada
    assert all(f["sanitizado"] for f in rel["fluxos"] if f["rotulo"] == "localizacao")


@precisa_node
@pytest.mark.skipif(not (APP / "src").exists(), reason="app GS-MOBILE-AQUENDA não está ao lado")
def test_mutacao_no_app_real_e_pega(tmp_path):
    copia = tmp_path / "app"
    shutil.copytree(APP / "src", copia / "src")
    shutil.copy(APP / "tsconfig.json", copia / "tsconfig.json")
    agenda = copia / "src" / "app" / "(abas)" / "agenda.tsx"
    codigo = agenda.read_text(encoding="utf-8")
    alvo = "    setLembretes(itens);"
    assert alvo in codigo
    agenda.write_text(codigo.replace(alvo, alvo + "\n    console.log('debug', ls);"), encoding="utf-8")
    rel = analisar_app(copia)
    assert any(f["rotulo"] == "agenda" and f["sumidouro"] == "log" and f["veredito"] == "violacao" for f in rel["fluxos"])
