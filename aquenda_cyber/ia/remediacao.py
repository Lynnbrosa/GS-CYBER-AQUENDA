"""Tradução via IA: o Claude transforma cada falha técnica num alerta de risco real ao cidadão.

Privacidade: o modelo nunca recebe o dado. Só recebe o tipo do dado, onde ele está, por onde
ele sai e a evidência já mascarada (ex.: "•••.•••.•••-25"). Sem credencial da API, ou se a
chamada falhar, um tradutor local (regras fixas) gera o alerta, e o painel diz qual foi usado.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

from ..auditoria import Falha

MODELO = "claude-opus-5-5"


class AlertaCidadao(BaseModel):
    titulo: str = Field(description="Uma frase curta, em linguagem simples, sem jargão. Até 80 caracteres.")
    risco_para_a_pessoa: str = Field(description="O que pode acontecer de verdade com a pessoa LGBTQIAPN+ que usa o Aquenda se isso vazar. Concreto, 1 a 3 frases.")
    quem_e_afetado: str = Field(description="Quem sofre o risco, por exemplo 'quem escreve nas salas de conversa'.")
    gravidade: Literal["baixa", "media", "alta", "critica"]
    como_corrigir: list[str] = Field(description="2 a 4 passos técnicos concretos para o time corrigir, cada um com o arquivo ou rota quando houver.")
    aviso_no_app: str = Field(description="Uma frase que o app poderia mostrar à pessoa para ela se proteger, em tom acolhedor.")


class AlertaGerado(BaseModel):
    falha_id: str
    alerta: AlertaCidadao
    gerado_por: Literal["claude", "local"]
    modelo: str | None = None
    observacao: str | None = None


SISTEMA = """Você traduz falhas de segurança e privacidade do Aquenda em alertas para pessoas comuns.

O Aquenda é um app para a população LGBTQIAPN+ de São Paulo, principalmente pessoas trans, travestis e em vulnerabilidade social. Ele mostra acolhimento, saúde trans no SUS, vagas afirmativas, salas de conversa moderadas e guarda a agenda de hormônio só no celular.

Para essas pessoas, um vazamento não é só um número: pode expor identidade de gênero contra a vontade, nome de registro, tratamento hormonal, HIV, endereço de casa de acolhimento, e levar a violência, perda de emprego ou rompimento familiar.

Regras:
- Escreva em português do Brasil, simples, direto, sem termos técnicos no título, no risco e no aviso.
- Seja proporcional: não exagere a gravidade. Dado público de instituição não é risco à pessoa.
- No "como corrigir", seja técnico e específico (rota, arquivo, mudança), porque é para o time.
- Você só recebe a evidência mascarada; nunca tente reconstruir o dado."""


def _payload(f: Falha) -> dict:
    """O que vai para o modelo: nada de valor original, só a descrição mascarada da falha."""
    return {
        "componente": {"app": "app no celular", "api_csharp": "API C# (catálogo e salas de conversa)", "api_soa": "FastAPI (vagas e CNES)"}.get(f.componente, f.componente),
        "tipo_de_falha": f.tipo,
        "dado": f.nome_dado,
        "categoria_lgpd": f.sensibilidade,
        "por_onde_sai": f.exposicao,
        "onde": f.origem,
        "evidencia_mascarada": f.evidencia,
        "ocorrencias": f.ocorrencias,
        "detalhes": f.detalhes[:6],
    }


# ---------------------------------------------------------------- tradutor local

_RISCO_POR_DADO = {
    "Dado de saúde": "Quem lê pode descobrir o tratamento hormonal, um diagnóstico como HIV ou depressão, e usar isso para expor, discriminar ou ameaçar a pessoa.",
    "Nome de registro (nome morto)": "O nome de registro exposto revela que a pessoa é trans e pode ser usado para humilhar, perseguir ou tirar dela o direito ao nome social.",
    "Identidade de gênero ou orientação": "Expõe a identidade ou orientação de alguém sem consentimento, o que pode levar a violência, demissão ou rompimento com a família.",
    "CPF": "Com o CPF, qualquer pessoa descobre o nome de registro e outros dados na base pública, e pode aplicar golpes.",
    "Cartão Nacional de Saúde (CNS)": "O Cartão SUS liga a pessoa ao prontuário e ao histórico de atendimentos na rede pública.",
    "Senha ou PIN": "Quem tiver a senha ou o PIN entra no app ou na conta e vê tudo o que a pessoa guardou.",
    "Token ou chave de acesso": "Quem tiver a chave pode agir em nome do sistema ou da pessoa: ler, apagar ou mandar dados.",
    "Telefone": "O telefone permite achar, assediar ou expor a pessoa fora do espaço moderado.",
    "E-mail": "O e-mail permite contato direto fora do app e pode revelar o nome verdadeiro.",
    "Endereço residencial": "Mostra onde a pessoa mora ou dorme, o que é grave para quem está em situação de violência.",
    "Localização precisa": "Mostra onde a pessoa está, quase ao metro.",
    "Agenda de hormônio": "A agenda revela que a pessoa faz hormonização, o remédio e o horário: é o retrato da transição dela, que o contrato do Aquenda promete nunca tirar do celular.",
    "Consulta médica": "Revela onde e quando a pessoa vai a uma consulta (por exemplo no ambulatório trans), o que expõe a transição e permite encontrá-la.",
    "PIN do app": "Quem tiver o PIN abre o modo discreto e vê a agenda e as conversas da pessoa.",
    "Token das salas": "Quem tiver o token escreve nas salas se passando pela pessoa.",
}
_GRAVIDADE = {"dado_pessoal_sensivel": "alta", "credencial": "alta", "dado_pessoal": "media"}
_SAIDA = {
    "resposta_api": "a API entrega isso a qualquer um que chamar a rota",
    "rede": "o dado sai do celular pela internet",
    "link_externo": "o dado vai para outro app ou site",
    "log": "o dado fica gravado em log, que muita gente da equipe e de ferramentas lê",
    "banco_servidor": "o dado fica guardado no servidor",
    "repositorio": "o dado está no código publicado no GitHub",
    "armazenamento_sem_cifra": "o dado fica em texto puro no celular",
    "notificacao": "o dado aparece na tela bloqueada",
    "area_de_transferencia": "qualquer app do celular consegue ler",
}
_CORRECAO = {
    "pii_em_resposta": ["Exigir o token de participante (X-Token-Chat) também para ler as mensagens, não só para enviar.", "Aplicar o GuardaDeSaida (aquenda_cyber.guarda) na API para mascarar dado sensível na resposta.", "Reduzir o tempo de guarda das mensagens e avisar nas regras da sala."],
    "pii_em_banco": ["Cifrar a coluna ou guardar só o necessário.", "Apagar automaticamente depois do prazo (a API já tem Chat:DiasRetencao).", "Restringir quem lê o banco na VM."],
    "pii_em_log": ["Instalar o FiltroPII (aquenda_cyber.guarda.instalar_filtro) nos loggers da API.", "Rodar a auditoria de novo para confirmar."],
    "pii_no_repositorio": ["Tirar o dado do arquivo e do histórico do Git.", "Trocar a credencial exposta.", "Usar variável de ambiente fora do repositório."],
    "vazamento_no_codigo": ["Remover a chamada que leva o dado para fora do celular.", "Se for preciso enviar, mandar só um valor derivado (contagem, hash, data) e registrar o fluxo na política do taint.", "Rodar o taint analysis de novo (npm run taint) para confirmar zero violações."],
}


def traduzir_local(f: Falha) -> AlertaCidadao:
    saida = _SAIDA.get(f.exposicao, f.exposicao)
    risco = _RISCO_POR_DADO.get(f.nome_dado, "Expõe um dado pessoal de quem usa o Aquenda.")
    gravidade = _GRAVIDADE.get(f.sensibilidade, "media")
    if f.exposicao in ("resposta_api", "link_externo", "repositorio") and gravidade == "alta":
        gravidade = "critica"
    return AlertaCidadao(
        titulo=f"{f.nome_dado} exposto: {saida}"[:80],
        risco_para_a_pessoa=f"{risco} Aqui, {saida}.",
        quem_e_afetado={"api_csharp": "quem usa as salas e o catálogo", "api_soa": "quem procura vagas e saúde", "app": "quem usa o app no celular"}.get(f.componente, "quem usa o Aquenda"),
        gravidade=gravidade,
        como_corrigir=_CORRECAO.get(f.tipo, ["Revisar a falha e rodar a auditoria de novo."]),
        aviso_no_app="Cuidado com o que você conta aqui: evite nome de registro, documentos e detalhes de saúde que identifiquem você.",
    )


# ---------------------------------------------------------------- Claude


def _chave_cache(f: Falha) -> str:
    return hashlib.sha256(json.dumps(_payload(f), sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def traduzir_com_claude(f: Falha, cliente: anthropic.Anthropic) -> AlertaCidadao:
    resposta = cliente.beta.messages.parse(
        model=MODELO,
        max_tokens=4000,
        # se um classificador recusar (o tema é segurança), a API tenta outro modelo na mesma chamada
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"effort": "low"},
        system=SISTEMA,
        messages=[{"role": "user", "content": "Traduza esta falha num alerta.\n\n" + json.dumps(_payload(f), ensure_ascii=False, indent=2)}],
        output_format=AlertaCidadao,
    )
    if resposta.stop_reason == "refusal" or resposta.parsed_output is None:
        raise RuntimeError(f"o modelo não devolveu o alerta (stop_reason={resposta.stop_reason})")
    return resposta.parsed_output


class Tradutor:
    """Traduz falhas com o Claude quando há credencial; cai para o tradutor local quando não há."""

    def __init__(self, cliente: anthropic.Anthropic | None = None, cache: Path | None = None, usar_claude: bool | None = None):
        self.cache_arquivo = cache
        self.cache: dict[str, dict] = {}
        if cache and cache.exists():
            self.cache = json.loads(cache.read_text(encoding="utf-8"))
        self.motivo_local: str | None = None
        self.cliente = cliente
        if self.cliente is None and usar_claude is not False:
            try:
                self.cliente = anthropic.Anthropic()
            except anthropic.AnthropicError as e:  # sem credencial no ambiente
                self.motivo_local = f"sem credencial da API ({type(e).__name__}); configure ANTHROPIC_API_KEY"
        if usar_claude is False:
            self.cliente = None
            self.motivo_local = "IA desligada nesta execução"

    def traduzir(self, f: Falha) -> AlertaGerado:
        chave = _chave_cache(f)
        if chave in self.cache:
            return AlertaGerado.model_validate(self.cache[chave])
        gerado: AlertaGerado
        if self.cliente is not None:
            try:
                alerta = traduzir_com_claude(f, self.cliente)
                gerado = AlertaGerado(falha_id=f.id, alerta=alerta, gerado_por="claude", modelo=MODELO)
            except anthropic.AuthenticationError:
                self.cliente, self.motivo_local = None, "credencial da API recusada"
                gerado = self._local(f)
            except anthropic.RateLimitError:
                gerado = self._local(f, "limite de uso da API atingido; usado o tradutor local")
            except anthropic.APIStatusError as e:
                gerado = self._local(f, f"API respondeu {e.status_code}; usado o tradutor local")
            except anthropic.APIConnectionError:
                gerado = self._local(f, "sem conexão com a API; usado o tradutor local")
            except RuntimeError as e:
                gerado = self._local(f, str(e))
            except TypeError as e:
                # o SDK só descobre na hora da chamada que não há credencial no ambiente
                if "authentication" not in str(e):
                    raise
                self.cliente, self.motivo_local = None, "sem credencial da API; configure ANTHROPIC_API_KEY para usar o Claude"
                gerado = self._local(f)
        else:
            gerado = self._local(f)
        if gerado.gerado_por == "claude":
            self.cache[chave] = gerado.model_dump()
            if self.cache_arquivo:
                self.cache_arquivo.parent.mkdir(parents=True, exist_ok=True)
                self.cache_arquivo.write_text(json.dumps(self.cache, ensure_ascii=False, indent=2), encoding="utf-8")
        return gerado

    def _local(self, f: Falha, observacao: str | None = None) -> AlertaGerado:
        return AlertaGerado(falha_id=f.id, alerta=traduzir_local(f), gerado_por="local", observacao=observacao or self.motivo_local)
