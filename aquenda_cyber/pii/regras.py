"""Regras de PII do Aquenda.

Cada regra encontra candidatos por padrão, confirma com validador (dígito verificador, DDD,
entropia...) e ajusta a confiança pelo contexto em volta. Regra de saúde e de identidade de
gênero só dispara quando o termo está ligado a uma pessoa: "hormonização" numa lista de
serviços do SUS não é dado pessoal; "tomo 2 mg de estradiol" é dado pessoal sensível.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .modelo import Achado, Sensibilidade, mascarar, mascarar_tudo
from .normalizacao import TextoNormalizado, sem_acento
from .validadores import cns_valido, cpf_valido, entropia_shannon, luhn_valido, telefone_br_valido

JANELA = 48  # caracteres de contexto para cada lado


@dataclass(frozen=True)
class Candidato:
    inicio: int  # no texto normalizado
    fim: int
    valor: str
    confianca: float
    motivo: str


class Regra(ABC):
    id: str
    nome: str
    sensibilidade: Sensibilidade
    #: palavras que aumentam a confiança quando aparecem perto
    contexto: tuple[str, ...] = ()
    #: sem nenhuma palavra de contexto por perto, a regra não dispara
    exige_contexto: bool = False

    @abstractmethod
    def candidatos(self, texto: str) -> list[Candidato]: ...

    def mascarar(self, valor: str) -> str:
        return mascarar(valor)

    # ------------------------------------------------------------------

    def ha_contexto(self, texto_sa: str, inicio: int, fim: int, palavras: tuple[str, ...] | None = None) -> bool:
        trecho = texto_sa[max(0, inicio - JANELA) : fim + JANELA]
        return any(re.search(rf"(?<![a-z]){re.escape(p)}(?![a-z])" if not p.endswith(("d", "v")) or " " in p else rf"(?<![a-z]){re.escape(p)}", trecho) for p in (palavras or self.contexto))

    def encontrar(self, tn: TextoNormalizado) -> list[Achado]:
        texto_sa = sem_acento(tn.normal)
        achados = []
        for c in self.candidatos(tn.normal):
            tem_ctx = bool(self.contexto) and self.ha_contexto(texto_sa, c.inicio, c.fim)
            if self.exige_contexto and not tem_ctx:
                continue
            confianca = min(1.0, c.confianca + (0.1 if tem_ctx and not self.exige_contexto else 0))
            ini, fim = tn.para_original(c.inicio, c.fim)
            original = tn.original[ini:fim]
            achados.append(
                Achado(
                    regra=self.id,
                    nome=self.nome,
                    sensibilidade=self.sensibilidade,
                    inicio=ini,
                    fim=fim,
                    mascarado=self.mascarar(original),
                    confianca=round(confianca, 2),
                    motivo=c.motivo + (" Palavra de contexto por perto." if tem_ctx else ""),
                )
            )
        return achados


class RegraPorPadrao(Regra):
    """Regra que é um padrão (regex) mais um validador opcional."""

    padrao: re.Pattern[str]
    confianca_base: float = 0.8
    motivo_base: str = ""

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        return True

    def candidatos(self, texto: str) -> list[Candidato]:
        saida = []
        for m in self.padrao.finditer(texto):
            grupo = "valor" if "valor" in self.padrao.groupindex else 0
            valor = m.group(grupo)
            if valor and self.validar(valor, m):
                saida.append(Candidato(m.start(grupo), m.end(grupo), valor, self.confianca_base, self.motivo_base))
        return saida


# ---------------------------------------------------------------- documentos


class RegraCPF(RegraPorPadrao):
    id, nome, sensibilidade = "cpf", "CPF", Sensibilidade.PESSOAL
    # aceita pontuação comum, espaços e o CPF "espalhado" com separadores entre os dígitos
    padrao = re.compile(r"(?<![\d])(?P<valor>\d{3}[.\s]?\d{3}[.\s]?\d{3}[-.\s/]?\d{2}|(?:\d[\s.\-]){10}\d)(?![\d])")
    contexto = ("cpf", "c.p.f", "cadastro de pessoa")
    confianca_base = 0.85
    motivo_base = "Número de 11 dígitos com dígitos verificadores de CPF válidos."

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        return cpf_valido(valor)


class RegraCNS(RegraPorPadrao):
    id, nome, sensibilidade = "cns", "Cartão Nacional de Saúde (CNS)", Sensibilidade.SENSIVEL
    padrao = re.compile(r"(?<![\d])(?P<valor>[12789]\d{2}[\s.]?\d{4}[\s.]?\d{4}[\s.]?\d{4})(?![\d])")
    contexto = ("cns", "cartao sus", "cartao do sus", "cartao nacional de saude", "sus")
    confianca_base = 0.85
    motivo_base = "Número de 15 dígitos que passa na verificação do Cartão SUS. Liga a pessoa ao prontuário do SUS."

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        return cns_valido(valor)


class RegraRG(RegraPorPadrao):
    id, nome, sensibilidade = "rg", "RG", Sensibilidade.PESSOAL
    padrao = re.compile(r"(?<![\d])(?P<valor>\d{1,2}\.?\d{3}\.?\d{3}-?[\dxX])(?![\d])")
    contexto = ("rg", "identidade", "registro geral", "carteira de identidade")
    exige_contexto = True
    confianca_base = 0.75
    motivo_base = "Número no formato de RG ao lado da palavra RG ou identidade."


class RegraCartao(RegraPorPadrao):
    id, nome, sensibilidade = "cartao_credito", "Cartão de crédito", Sensibilidade.CREDENCIAL
    padrao = re.compile(r"(?<![\d])(?P<valor>[3-6]\d{3}(?:[ -]?\d{4}){2}[ -]?\d{4}(?:[ -]?\d{1,3})?)(?![\d])")
    contexto = ("cartao", "credito", "debito", "visa", "master", "elo", "cvv")
    confianca_base = 0.7
    motivo_base = "Número que passa no algoritmo de Luhn usado pelos cartões."

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        return luhn_valido(valor) and not cpf_valido(valor)


# ---------------------------------------------------------------- contato e localização


class RegraTelefone(RegraPorPadrao):
    id, nome, sensibilidade = "telefone", "Telefone", Sensibilidade.PESSOAL
    padrao = re.compile(r"(?<![\d])(?P<valor>(?:\+?55[\s.-]?)?\(?\d{2}\)?[\s.-]?(?:9[\s.-]?)?\d{4}[\s.-]?\d{4})(?![\d])")
    contexto = ("tel", "fone", "celular", "whats", "zap", "liga", "contato", "me chama")
    confianca_base = 0.7
    motivo_base = "Número com DDD brasileiro válido."

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        return telefone_br_valido(valor)


class RegraEmail(RegraPorPadrao):
    id, nome, sensibilidade = "email", "E-mail", Sensibilidade.PESSOAL
    padrao = re.compile(r"(?P<valor>[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})")
    confianca_base = 0.9
    motivo_base = "Endereço de e-mail."

    def mascarar(self, valor: str) -> str:
        usuario, _, dominio = valor.partition("@")
        return (usuario[:1] + "•" * max(1, len(usuario) - 1)) + "@" + dominio


class RegraEndereco(RegraPorPadrao):
    id, nome, sensibilidade = "endereco", "Endereço residencial", Sensibilidade.PESSOAL
    padrao = re.compile(
        r"(?P<valor>\b(?:rua|r\.|avenida|av\.|travessa|tv\.|alameda|al\.|pra[cç]a|estrada|rodovia)\s+"
        r"[A-Za-zÀ-ÿ0-9 .'\-]{2,40}?,?\s*(?:n[ºo°.]?\s*)?\d{1,5}\b)",
        re.IGNORECASE,
    )
    # endereço de serviço público não é dado pessoal; só conta quando é onde a pessoa mora
    contexto = ("moro", "minha casa", "meu endereco", "resido", "residencia", "endereco residencial", "durmo", "fico na")
    exige_contexto = True
    confianca_base = 0.75
    motivo_base = "Endereço com número ao lado de 'moro' ou 'minha casa'."

    def mascarar(self, valor: str) -> str:
        palavras = valor.split()
        return palavras[0] + " " + mascarar_tudo(" ".join(palavras[1:]))


class RegraCEP(RegraPorPadrao):
    id, nome, sensibilidade = "cep", "CEP residencial", Sensibilidade.PESSOAL
    padrao = re.compile(r"(?<![\d])(?P<valor>\d{5}-?\d{3})(?![\d])")
    contexto = ("cep",)
    exige_contexto = True
    confianca_base = 0.6
    motivo_base = "CEP informado junto da palavra CEP."


class RegraCoordenada(RegraPorPadrao):
    id, nome, sensibilidade = "coordenada_precisa", "Localização precisa", Sensibilidade.PESSOAL
    # 5 casas decimais ou mais = cerca de 1 metro. O app manda 4 (uns 11 m) de propósito.
    padrao = re.compile(r"(?P<valor>-?\d{1,2}\.\d{5,}\s*,\s*-?\d{1,3}\.\d{5,})")
    confianca_base = 0.8
    motivo_base = "Latitude e longitude com precisão de cerca de 1 metro: mostra onde a pessoa está."


class RegraNascimento(RegraPorPadrao):
    id, nome, sensibilidade = "data_nascimento", "Data de nascimento", Sensibilidade.PESSOAL
    padrao = re.compile(
        r"(?:nasci(?:da|do|de)?\s+(?:em|no dia)|data\s+de\s+nascimento|nascimento|d\.?n\.?)\s*[:\-]?\s*(?P<valor>\d{1,2}/\d{1,2}/\d{2,4})",
        re.IGNORECASE,
    )
    confianca_base = 0.85
    motivo_base = "Data ao lado de 'nascimento' ou 'nasci em'."


# ---------------------------------------------------------------- credenciais


EXEMPLO = re.compile(r"(teste|exemplo|example|fake|dummy|nao-e-real|placeholder|xxxx|changeme)", re.IGNORECASE)
PLACEHOLDERS = re.compile(r"^(\*+|x+|•+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|senha|password|changeme|\.\.\.)$", re.IGNORECASE)


class RegraSenha(RegraPorPadrao):
    id, nome, sensibilidade = "senha", "Senha ou PIN", Sensibilidade.CREDENCIAL
    padrao = re.compile(
        r"(?:senha|password|passwd|pwd|pin|c[oó]digo\s+de\s+acesso)[\"']?\s*(?:[:=]|é|e|eh)\s*[\"']?(?P<valor>[^\s\"',;}]{3,64})",
        re.IGNORECASE,
    )
    confianca_base = 0.9
    motivo_base = "Valor escrito logo depois de 'senha' ou 'PIN'."

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        if valor.startswith(("<", "[", "{")):
            return False  # "<sua senha>", "[senha]", "{senha}" são modelos de texto
        return not PLACEHOLDERS.match(valor) and not valor.lower().startswith(("http", "$", "process.env", "os.environ"))

    def mascarar(self, valor: str) -> str:
        return "•" * len(valor)  # senha não mostra nem a pontuação


class RegraToken(Regra):
    id, nome, sensibilidade = "token", "Token ou chave de acesso", Sensibilidade.CREDENCIAL

    PADROES = (
        (re.compile(r"(?P<valor>sk-ant-[A-Za-z0-9\-_]{20,})"), 0.99, "Chave da API da Anthropic."),
        (re.compile(r"(?P<valor>AKIA[0-9A-Z]{16})"), 0.95, "Chave de acesso da AWS."),
        (re.compile(r"(?P<valor>eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,})"), 0.95, "Token JWT."),
        (re.compile(r"[Bb]earer\s+(?P<valor>[A-Za-z0-9\-._~+/]{20,}=*)"), 0.9, "Token no cabeçalho Authorization."),
        (
            re.compile(
                r"(?:x-chave-operador|x-token-chat|x-participante|api[_-]?key|app[_-]?key|app[_-]?id|secret|token|chave)"
                r"[\"']?\s*[:=]\s*[\"']?(?P<valor>[A-Za-z0-9\-_.]{16,})",
                re.IGNORECASE,
            ),
            0.85,
            "Valor aleatório ao lado do nome de uma chave ou token.",
        ),
    )

    def candidatos(self, texto: str) -> list[Candidato]:
        saida = []
        for padrao, conf, motivo in self.PADROES:
            for m in padrao.finditer(texto):
                v = m.group("valor")
                # nome de variável ("tokenHash", "participanteToken") e texto comum não são segredo:
                # exige aleatoriedade, e segredo curto quase sempre mistura letra com número
                if len(v) < 32 and (entropia_shannon(v) < 3.3 or v.replace("_", "").replace("-", "").isalpha()):
                    continue
                if EXEMPLO.search(v) or re.fullmatch(r"[a-z]+(?:[._-][a-z]+)+", v):
                    continue  # "TOKEN-DE-TESTE", "chave-de-exemplo", "aquenda.salas.participante"
                saida.append(Candidato(m.start("valor"), m.end("valor"), v, conf, motivo))
        return saida

    def mascarar(self, valor: str) -> str:
        return valor[:4] + "•" * max(4, len(valor) - 4)


# ---------------------------------------------------------------- dados sensíveis (LGPD art. 5º, II)

# Âncoras: o termo de saúde só vira dado pessoal quando está ligado a alguém.
ANCORAS_PESSOAIS = (
    "tomo", "tomei", "uso", "usei", "aplico", "apliquei", "faco", "fiz", "estou", "tenho", "tive",
    "meu", "minha", "meus", "minhas", "sou", "fui diagnosticad", "diagnosticad", "descobri", "comecei",
    "deu positivo", "deu reagente", "meu resultado",
    "ela tem", "ele tem", "elu tem", "dela", "dele", "delu",
)

MEDICAMENTOS = (
    "estradiol", "valerato de estradiol", "cipionato de testosterona", "undecilato de testosterona",
    "testosterona", "ciproterona", "acetato de ciproterona", "espironolactona", "finasterida",
    "progesterona", "bloqueador hormonal", "triptorrelina", "leuprorrelina", "deposteron", "durateston",
    "nebido", "perlutan", "androcur", "tarv", "antirretrovira", "truvada", "dolutegravir", "tenofovir",
)

CONDICOES = (
    "hiv", "aids", "soropositiv", "sifilis", "hepatite b", "hepatite c", "tuberculose", "hpv", "herpes",
    "depressao", "ansiedade", "transtorno bipolar", "bipolaridade", "esquizofrenia", "borderline",
    "ideacao suicida", "tentativa de suicidio", "automutilacao", "disforia de genero", "incongruencia de genero",
    "dependencia quimica", "alcoolismo",
)

TRATAMENTOS = (
    "prep", "pep", "hormonizacao", "hormonioterapia", "terapia hormonal", "processo transexualizador",
    "mamoplastia", "mastectomia masculinizadora", "neovagina", "vaginoplastia", "faloplastia",
    "laudo psiquiatrico", "laudo psicologico", "internacao psiquiatrica", "caps",
)

DOSE = re.compile(r"\b\d+(?:[.,]\d+)?\s?(?:mg|ml|mcg|µg|ui|ampolas?|comprimidos?|gotas)\b", re.IGNORECASE)
CID = re.compile(r"\bcid[- ]?(?:10|11)?\s*[:\-]?\s*(?P<valor>[a-z]\d{2}(?:\.\d{1,2})?|[a-z]{2}\d{2}(?:\.\d)?)\b", re.IGNORECASE)


# Termos que são radical de palavra (casam com o começo: "soropositiva", "antirretrovirais").
RADICAIS = {"soropositiv", "antirretrovira", "diagnosticad"}


def _termos(texto_sa: str, termos: tuple[str, ...]) -> list[tuple[int, int, str]]:
    """Acha o termo como palavra inteira ("prep" não casa com "preparar"), salvo os radicais."""
    achados = []
    for t in termos:
        fim = "" if t in RADICAIS else r"(?![a-z])"
        for m in re.finditer(rf"(?<![a-z]){re.escape(t)}{fim}", texto_sa):
            achados.append((m.start(), m.end(), t))
    return achados


class RegraSaude(Regra):
    id, nome, sensibilidade = "saude", "Dado de saúde", Sensibilidade.SENSIVEL
    contexto = ANCORAS_PESSOAIS

    def candidatos(self, texto: str) -> list[Candidato]:
        sa = sem_acento(texto)  # sem_acento preserva o tamanho em texto já NFKC (só tira combinantes)
        if len(sa) != len(texto):
            sa = sa[: len(texto)].ljust(len(texto))
        saida = []
        for ini, fim, termo in _termos(sa, MEDICAMENTOS):
            perto = sa[max(0, ini - JANELA) : fim + JANELA]
            dose = DOSE.search(perto)
            if dose:
                saida.append(Candidato(ini, fim, termo, 0.95, f"Medicamento ({termo}) com dose por perto: diz o tratamento de alguém."))
            elif self.ha_contexto(sa, ini, fim):
                saida.append(Candidato(ini, fim, termo, 0.85, f"Medicamento ({termo}) ligado a uma pessoa."))
        for ini, fim, termo in _termos(sa, CONDICOES) + _termos(sa, TRATAMENTOS):
            if self.ha_contexto(sa, ini, fim):
                saida.append(Candidato(ini, fim, termo, 0.85, f"Condição ou tratamento de saúde ({termo}) ligado a uma pessoa."))
        for m in CID.finditer(texto):
            saida.append(Candidato(m.start("valor"), m.end("valor"), m.group("valor"), 0.9, "Código CID de diagnóstico."))
        return saida

    def encontrar(self, tn: TextoNormalizado) -> list[Achado]:
        # a âncora já foi exigida em candidatos(); aqui não soma bônus de contexto de novo
        achados = []
        for c in self.candidatos(tn.normal):
            ini, fim = tn.para_original(c.inicio, c.fim)
            achados.append(
                Achado(self.id, self.nome, self.sensibilidade, ini, fim, mascarar_tudo(tn.original[ini:fim]), c.confianca, c.motivo)
            )
        return achados


class RegraNomeDeRegistro(RegraPorPadrao):
    """Nome de registro (o "nome morto") de uma pessoa trans: expor isso é violência e risco real."""

    id, nome, sensibilidade = "nome_registro", "Nome de registro (nome morto)", Sensibilidade.SENSIVEL
    NOME = r"[A-ZÀ-Ý][a-zà-ÿ]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]+){0,4}"
    padrao = re.compile(
        r"(?:nome\s+(?:de\s+registro|civil|morto|antigo|de\s+batismo|no\s+rg|do\s+rg)|deadname|"
        r"antes\s+(?:eu\s+)?(?:me\s+chamava|era\s+chamad[oae])|no\s+(?:rg|documento)\s+(?:ainda\s+)?(?:est[aá]|consta|aparece))"
        r"\s*(?:[:\-=]|é|e|era|como)?\s*[\"']?(?P<valor>" + NOME + r")",
        re.IGNORECASE,
    )
    confianca_base = 0.95
    motivo_base = "Nome de registro de uma pessoa trans, escrito ao lado de 'nome de registro' ou 'nome morto'."

    def validar(self, valor: str, m: re.Match[str]) -> bool:
        return valor[0].isupper()

    def mascarar(self, valor: str) -> str:
        return " ".join(p[0] + "•" * (len(p) - 1) for p in valor.split())


class RegraIdentidade(RegraPorPadrao):
    """Identidade de gênero ou orientação sexual dita em primeira pessoa (vida sexual: art. 5º, II)."""

    id, nome, sensibilidade = "identidade_genero_orientacao", "Identidade de gênero ou orientação", Sensibilidade.SENSIVEL
    padrao = re.compile(
        r"\b(?:sou|eu\s+sou|me\s+identifico\s+como|me\s+assumi|sai\s+do\s+armario\s+como|virei)\s+(?:uma?\s+)?"
        r"(?P<valor>mulher\s+trans|homem\s+trans|pessoa\s+trans|travesti|n[aã]o[\s-]?bin[aá]ri[oae]|transexual|transgenero|trans|"
        r"gay|l[eé]sbica|bissexual|bi|pansexual|intersexo|assexual)\b",
        re.IGNORECASE,
    )
    confianca_base = 0.7
    motivo_base = "Identidade de gênero ou orientação sexual dita em primeira pessoa."

    def mascarar(self, valor: str) -> str:
        return "[identidade]"


TODAS = (
    RegraCPF(), RegraCNS(), RegraRG(), RegraCartao(), RegraTelefone(), RegraEmail(), RegraEndereco(),
    RegraCEP(), RegraCoordenada(), RegraNascimento(), RegraSenha(), RegraToken(), RegraSaude(),
    RegraNomeDeRegistro(), RegraIdentidade(),
)
