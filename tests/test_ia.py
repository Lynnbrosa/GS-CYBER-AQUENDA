"""Remediação via IA sem rede: o cliente do Claude é falso. Confere o que vai para o modelo
(nunca o dado original), a chamada com saída estruturada e as quedas para o tradutor local."""

import json
from types import SimpleNamespace

import anthropic
import httpx

from aquenda_cyber.auditoria import Falha
from aquenda_cyber.ia.remediacao import MODELO, AlertaCidadao, Tradutor, _payload, traduzir_local

CPF_REAL = "529.982.247-25"


def falha(**kw) -> Falha:
    base = dict(
        id="abc123", componente="api_csharp", tipo="pii_em_resposta", titulo="Dado de saúde em resposta da API",
        regra="saude", nome_dado="Dado de saúde", sensibilidade="dado_pessoal_sensivel", exposicao="resposta_api",
        evidencia="•••••••••", origem="GET /api/chat/salas/{id}/mensagens:$[*].texto", ocorrencias=4, confianca=0.95,
        detalhes=["Medicamento (estradiol) com dose por perto: diz o tratamento de alguém."],
    )
    base.update(kw)
    f = Falha(**base)
    f.calcular_pontos()
    return f


class ClienteFalso:
    def __init__(self, resposta=None, erro=None):
        self.chamadas = []
        self._resposta, self._erro = resposta, erro
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kw):
        self.chamadas.append(kw)
        if self._erro:
            raise self._erro
        return self._resposta


ALERTA = AlertaCidadao(
    titulo="Mensagens sobre saúde podem ser lidas por qualquer pessoa",
    risco_para_a_pessoa="Quem conta o tratamento hormonal na sala pode ser exposta.",
    quem_e_afetado="quem escreve nas salas",
    gravidade="alta",
    como_corrigir=["Exigir X-Token-Chat no GET de mensagens", "Mascarar dose na resposta"],
    aviso_no_app="Evite contar detalhes de saúde que identifiquem você.",
)


def test_o_modelo_nunca_recebe_o_dado_original():
    p = json.dumps(_payload(falha(evidencia="•••.•••.•••-25", nome_dado="CPF")), ensure_ascii=False)
    assert CPF_REAL not in p and "529" not in p
    assert "•••.•••.•••-25" in p


def test_chama_o_claude_com_saida_estruturada_e_fallback():
    cli = ClienteFalso(resposta=SimpleNamespace(stop_reason="end_turn", parsed_output=ALERTA))
    g = Tradutor(cliente=cli).traduzir(falha())
    assert g.gerado_por == "claude" and g.modelo == MODELO
    assert g.alerta.gravidade == "alta"
    kw = cli.chamadas[0]
    assert kw["model"] == "claude-opus-5-5"
    assert kw["output_format"] is AlertaCidadao
    assert kw["fallbacks"] == "default" and "server-side-fallback-2026-07-01" in kw["betas"]
    assert "LGBTQIAPN+" in kw["system"]


def test_recusa_do_modelo_cai_para_o_local():
    cli = ClienteFalso(resposta=SimpleNamespace(stop_reason="refusal", parsed_output=None))
    g = Tradutor(cliente=cli).traduzir(falha())
    assert g.gerado_por == "local" and "refusal" in g.observacao


def test_sem_conexao_cai_para_o_local():
    erro = anthropic.APIConnectionError(request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
    g = Tradutor(cliente=ClienteFalso(erro=erro)).traduzir(falha())
    assert g.gerado_por == "local" and "sem conexão" in g.observacao


def test_cache_evita_pagar_duas_vezes(tmp_path):
    cli = ClienteFalso(resposta=SimpleNamespace(stop_reason="end_turn", parsed_output=ALERTA))
    t = Tradutor(cliente=cli, cache=tmp_path / "cache.json")
    t.traduzir(falha())
    t2 = Tradutor(cliente=cli, cache=tmp_path / "cache.json")
    assert t2.traduzir(falha()).gerado_por == "claude"
    assert len(cli.chamadas) == 1


def test_tradutor_local_e_proporcional():
    saude = traduzir_local(falha())
    assert saude.gravidade == "critica"  # sensível + API aberta
    assert "tratamento hormonal" in saude.risco_para_a_pessoa
    tel = traduzir_local(falha(nome_dado="Telefone", sensibilidade="dado_pessoal", exposicao="banco_servidor", tipo="pii_em_banco"))
    assert tel.gravidade == "media"
    assert any("Cifrar" in p for p in tel.como_corrigir)


def test_sem_credencial_no_ambiente_cai_para_o_local():
    erro = TypeError('"Could not resolve authentication method. Expected one of api_key, auth_token"')
    t = Tradutor(cliente=ClienteFalso(erro=erro))
    g = t.traduzir(falha())
    assert g.gerado_por == "local" and "ANTHROPIC_API_KEY" in g.observacao
    assert t.cliente is None  # não tenta de novo a cada falha
