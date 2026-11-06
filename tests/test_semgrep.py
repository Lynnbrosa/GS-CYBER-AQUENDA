"""Regras de taint do Semgrep (rules/): pegam os vazamentos plantados e deixam os casos limpos em paz."""

import pytest

from aquenda_cyber.auditoria import falhas_do_semgrep
from aquenda_cyber.taint import REGRAS_CSHARP, REGRAS_TS, RAIZ, TaintIndisponivel, _semgrep, rodar_semgrep

pytestmark = pytest.mark.skipif(_semgrep() is None, reason="Semgrep não instalado")


def linhas(achados, regra=None):
    return sorted(a["linha"] for a in achados if regra is None or a["regra"] == regra)


def test_csharp_pega_os_cinco_vazamentos_e_nenhum_caso_limpo():
    achados = rodar_semgrep(RAIZ / "exemplos" / "csharp_vulneravel", REGRAS_CSHARP)
    assert linhas(achados, "aquenda-cs-dado-da-pessoa-no-log") == [13, 19, 26, 32]  # V1 texto, V2 req.Texto, V3 CEP, V4 token
    assert linhas(achados, "aquenda-cs-token-sem-hash") == [39]  # V5
    assert all(a["linha"] < 42 for a in achados)  # OK1 (tamanho), OK2 (mascarado), OK3 (hash) ficam de fora


def test_typescript_pega_os_vazamentos_dentro_da_funcao():
    achados = rodar_semgrep(RAIZ / "taint_ts" / "exemplos" / "vulneravel" / "src", REGRAS_TS)
    por_arquivo = {(a["arquivo"], a["linha"]) for a in achados}
    assert {("vazamentos.ts", 10), ("vazamentos.ts", 22), ("vazamentos.ts", 28), ("vazamentos.ts", 34),
            ("vazamentos.ts", 39), ("posicao.ts", 8), ("posicao.ts", 21)} == por_arquivo
    # o que atravessa funções (util.ts, formulário) fica para o analisador próprio, que segue o dado entre arquivos


def test_achado_vira_falha_com_a_saida_certa_e_sem_repetir_o_taint_proprio():
    achados = rodar_semgrep(RAIZ / "exemplos" / "csharp_vulneravel", REGRAS_CSHARP)
    falhas = falhas_do_semgrep(achados, "api_csharp")
    assert {f.exposicao for f in falhas} == {"log", "banco_servidor"}
    ts = rodar_semgrep(RAIZ / "taint_ts" / "exemplos" / "vulneravel" / "src", REGRAS_TS)
    assert len(falhas_do_semgrep(ts, "app", ja_vistas={"vazamentos.ts:10"})) == len(ts) - 1


def test_sem_semgrep_avisa_em_vez_de_quebrar(monkeypatch):
    import aquenda_cyber.taint as t

    monkeypatch.setattr(t, "_semgrep", lambda: None)
    with pytest.raises(TaintIndisponivel):
        t.rodar_semgrep(RAIZ, REGRAS_CSHARP)
