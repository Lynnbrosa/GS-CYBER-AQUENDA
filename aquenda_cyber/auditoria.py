"""Auditoria do protótipo Aquenda: junta o que cada verificação achou numa lista de falhas.

Fontes da auditoria:
- taint analysis do app (fluxos de dado sensível até saídas inseguras);
- respostas ao vivo das duas APIs (API C# e FastAPI), varridas pelo motor de PII;
- bancos SQLite das APIs;
- logs das APIs;
- arquivos versionados do app (segredo ou dado pessoal commitado).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .pii import Achado, MotorPII, Sensibilidade
from .pii.modelo import PESO_SENSIBILIDADE
from .taint import TaintIndisponivel, analisar_app

# Quanto pesa cada tipo de saída: quanto mais longe do celular e mais gente vê, maior.
PESO_EXPOSICAO = {
    "link_externo": 3.0,  # vai para outro app ou site
    "resposta_api": 3.0,  # API aberta: qualquer um que chamar recebe
    "repositorio": 3.0,  # commitado no GitHub
    "area_de_transferencia": 2.5,
    "rede": 2.0,  # sai do celular para uma API
    "log": 2.0,
    "armazenamento_sem_cifra": 2.0,
    "banco_servidor": 1.5,  # guardado no servidor, sem cifra por campo
    "notificacao": 1.5,  # aparece na tela bloqueada
}

NOME_DO_ROTULO = {
    "agenda": "Agenda de hormônio",
    "consultas": "Consulta médica",
    "pin": "PIN do app",
    "token_salas": "Token das salas",
    "localizacao": "Localização precisa",
}

ROTULO_SENSIBILIDADE = {
    "agenda": Sensibilidade.SENSIVEL,
    "consultas": Sensibilidade.SENSIVEL,
    "pin": Sensibilidade.CREDENCIAL,
    "token_salas": Sensibilidade.CREDENCIAL,
    "localizacao": Sensibilidade.PESSOAL,
}

# Caminhos que levam dado público de propósito: telefone e endereço de serviço, não de pessoa.
PERMITIDOS_RESPOSTA = [
    re.compile(r"\$\.itens\[\d+\]\.(telefone|endereco|bairro|cep)"),
    re.compile(r"\$\.itens\[\d+\]\.endereco\.\w+"),
    re.compile(r"\$\.resumo\.(telefone|endereco)(\.\w+)?"),
    re.compile(r"\$\.(telefone|endereco|bairro|cep)"),
    re.compile(r"\$\[\d+\]\.local\.endereco"),
]


# Colunas com contato público de instituição (unidade de saúde, serviço do catálogo).
PERMITIDOS_BANCO = re.compile(r":(estabelecimentos_cnes|Servicos|municipios)\.(telefone|endereco|bairro|cep|Endereco_\w+|Telefone)#", re.IGNORECASE)


@dataclass
class Falha:
    id: str
    componente: str  # app, api_csharp, api_soa
    tipo: str  # vazamento_no_codigo, pii_em_resposta, pii_em_banco, pii_em_log, pii_no_repositorio
    titulo: str  # título técnico curto
    regra: str  # regra de PII ou rótulo do taint
    nome_dado: str
    sensibilidade: str
    exposicao: str
    evidencia: str  # sempre mascarada
    origem: str
    ocorrencias: int
    confianca: float
    detalhes: list[str] = field(default_factory=list)
    pontos: float = 0.0

    def calcular_pontos(self) -> float:
        impacto = PESO_SENSIBILIDADE[Sensibilidade(self.sensibilidade)]
        exposicao = PESO_EXPOSICAO.get(self.exposicao, 1.0)
        volume = 1 + math.log10(max(1, self.ocorrencias))
        self.pontos = round(impacto * exposicao * self.confianca * volume, 2)
        return self.pontos


@dataclass
class Auditoria:
    quando: str
    falhas: list[Falha]
    controles: list[dict]  # o que foi verificado e está protegido
    fontes: dict[str, str]  # o que rodou e o que não rodou (com o motivo)
    indice: int = 0
    nivel: str = ""
    por_componente: dict[str, dict] = field(default_factory=dict)

    def como_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- índice


def indice_risco(pontos: float, escala: float) -> int:
    """0 a 100, saturando: muitas falhas pequenas não passam de 100, uma grave já pesa muito."""
    return round(100 * (1 - math.exp(-pontos / escala)))


def nivel_de(indice: int) -> str:
    if indice >= 80:
        return "crítico"
    if indice >= 50:
        return "alto"
    if indice >= 20:
        return "moderado"
    return "baixo"


def _id(*partes: str) -> str:
    return hashlib.sha1("|".join(partes).encode()).hexdigest()[:10]


# ---------------------------------------------------------------- coleta


def falhas_do_taint(relatorio: dict) -> tuple[list[Falha], list[dict]]:
    falhas, controles = [], []
    for f in relatorio["fluxos"]:
        if f["veredito"] == "permitido":
            controles.append({"componente": "app", "o_que": f"{f['rotulo']} → {f['sumidouro']}", "onde": f["onde"], "por_que": f["porque"]})
            continue
        sens = ROTULO_SENSIBILIDADE.get(f["rotulo"], Sensibilidade.PESSOAL)
        falhas.append(
            Falha(
                id=_id("taint", f["rotulo"], f["sumidouro"], f["onde"]),
                componente="app",
                tipo="vazamento_no_codigo",
                titulo=f"{NOME_DO_ROTULO.get(f['rotulo'], f['rotulo'])} chega a {f['sumidouro']}",
                regra=f["rotulo"],
                nome_dado=NOME_DO_ROTULO.get(f["rotulo"], f["rotulo"]),
                sensibilidade=sens.value,
                exposicao=f["sumidouro"],
                evidencia=f"{f['chamada']}(...)",
                origem=f["onde"],
                ocorrencias=1,
                confianca=0.9,
                detalhes=f["trilha"],
            )
        )
    return falhas, controles


def _agrupar(achados: list[Achado], componente: str, tipo: str, exposicao: str, prefixo: str, normalizar_origem) -> list[Falha]:
    grupos: dict[tuple, list[Achado]] = defaultdict(list)
    for a in achados:
        grupos[(normalizar_origem(a.origem), a.regra)].append(a)
    falhas = []
    for (origem, regra), lista in grupos.items():
        a = max(lista, key=lambda x: x.confianca)
        falhas.append(
            Falha(
                id=_id(tipo, componente, origem, regra),
                componente=componente,
                tipo=tipo,
                titulo=f"{a.nome} em {prefixo} ({origem})",
                regra=regra,
                nome_dado=a.nome,
                sensibilidade=a.sensibilidade.value,
                exposicao=exposicao,
                evidencia=a.mascarado,
                origem=origem,
                ocorrencias=len(lista),
                confianca=a.confianca,
                detalhes=sorted({x.motivo for x in lista})[:3],
            )
        )
    return falhas


def _rota_generica(origem: str) -> str:
    # "GET /api/vagas/17:$.descricao" -> "GET /api/vagas/{id}:$.descricao"; índices de lista viram [*]
    return re.sub(r"\[\d+\]", "[*]", re.sub(r"/\d+(?=[/:?]|$)", "/{id}", origem))


def falhas_das_respostas(motor: MotorPII, rotas: dict[str, list[str]], tempo_limite: float = 10.0) -> tuple[list[Falha], dict[str, str]]:
    """Chama cada rota GET e varre o JSON. `rotas` = {componente: [url, ...]}."""
    falhas, estado = [], {}
    for componente, urls in rotas.items():
        achados: list[Achado] = []
        ok = 0
        for url in urls:
            try:
                r = httpx.get(url, timeout=tempo_limite)
                if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
                    continue
                ok += 1
                rota = "GET " + httpx.URL(url).path
                for a in motor.varrer_estrutura(r.json()):
                    if not any(p.fullmatch(a.origem) for p in PERMITIDOS_RESPOSTA):
                        achados.append(_com_origem(a, f"{rota}:{a.origem}"))
            except httpx.HTTPError as e:
                estado[componente] = f"fora do ar: {type(e).__name__}"
        estado.setdefault(componente, f"{ok} de {len(urls)} rotas lidas")
        falhas += _agrupar(achados, componente, "pii_em_resposta", "resposta_api", "resposta da API", _rota_generica)
    return falhas, estado


def falhas_dos_bancos(motor: MotorPII, bancos: dict[str, Path]) -> tuple[list[Falha], dict[str, str]]:
    falhas, estado = [], {}
    for componente, caminho in bancos.items():
        if not caminho or not Path(caminho).exists():
            estado[f"banco_{componente}"] = "não encontrado"
            continue
        achados = [a for a in motor.varrer_sqlite(Path(caminho)) if not PERMITIDOS_BANCO.search(a.origem)]
        estado[f"banco_{componente}"] = f"{Path(caminho).name} lido"
        falhas += _agrupar(achados, componente, "pii_em_banco", "banco_servidor", "banco", lambda o: re.sub(r"#\d+$", "", o))
    return falhas, estado


def falhas_dos_logs(motor: MotorPII, logs: dict[str, list[Path]]) -> tuple[list[Falha], dict[str, str]]:
    falhas, estado = [], {}
    for componente, caminhos in logs.items():
        achados: list[Achado] = []
        lidos = [p for p in caminhos if Path(p).exists()]
        for p in lidos:
            achados += motor.varrer_arquivo(Path(p))
        estado[f"logs_{componente}"] = f"{len(lidos)} arquivo(s)"
        falhas += _agrupar(achados, componente, "pii_em_log", "log", "log", lambda o: Path(re.sub(r":\d+$", "", o)).name)
    return falhas, estado


def falhas_do_repositorio(motor: MotorPII, pasta: Path, componente: str = "app") -> list[Falha]:
    """Segredo ou dado pessoal commitado (código, fixtures, configs)."""
    if not pasta.exists():
        return []
    achados: list[Achado] = []
    ignorar = {"node_modules", ".git", ".expo", "android", "ios", "dist", "dist-apk", ".venv"}
    for arq in pasta.rglob("*"):
        if not arq.is_file() or ignorar & set(arq.parts) or arq.suffix.lower() not in {".ts", ".tsx", ".js", ".json", ".md", ".env", ".txt", ".yml", ".yaml"}:
            continue
        if arq.name in {"package-lock.json"}:
            continue
        relativo = arq.relative_to(pasta).as_posix()
        if re.search(r"\.(test|spec)\.[jt]sx?$", arq.name):
            continue  # teste tem amostra falsa de propósito (CPF gerado, chave de exemplo)
        eh_codigo = arq.suffix.lower() in {".ts", ".tsx", ".js", ".md", ".yml", ".yaml"}
        for a in motor.varrer_arquivo(arq):
            caminho_json = a.origem.split(":", 1)[1] if ":" in a.origem else a.origem
            if any(p.fullmatch(caminho_json) for p in PERMITIDOS_RESPOSTA):
                continue  # telefone/endereço público de serviço gravado em fixture
            if eh_codigo:
                # em código, só segredo com formato real (sk-ant, AKIA, JWT, Bearer); "pin: string" não é senha
                if a.regra != "token" or a.confianca < 0.9:
                    continue
            achados.append(_com_origem(a, relativo + ":" + a.origem.rsplit(":", 1)[-1]))
    return _agrupar(achados, componente, "pii_no_repositorio", "repositorio", "arquivo versionado", lambda o: o.rsplit(":", 1)[0])


def _com_origem(a: Achado, origem: str) -> Achado:
    from dataclasses import replace

    return replace(a, origem=origem)


# ---------------------------------------------------------------- tudo junto


def rotas_padrao(csharp: str | None, soa: str | None, limite_detalhes: int = 15) -> dict[str, list[str]]:
    rotas: dict[str, list[str]] = {}
    if csharp:
        base = csharp.rstrip("/")
        rotas["api_csharp"] = [f"{base}/api/servicos?tamanho=100", f"{base}/api/casas", f"{base}/api/rodas?dias=90", f"{base}/api/chat/salas", f"{base}/api/chat/regras"]
        try:
            for s in httpx.get(f"{base}/api/chat/salas", timeout=5).json():
                rotas["api_csharp"].append(f"{base}/api/chat/salas/{s['id']}/mensagens?limite=100")
            for s in httpx.get(f"{base}/api/servicos?tamanho=100", timeout=5).json()["itens"][:limite_detalhes]:
                rotas["api_csharp"].append(f"{base}/api/servicos/{s['id']}")
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass
    if soa:
        base = soa.rstrip("/")
        rotas["api_soa"] = [f"{base}/api/vagas?tamanho=100", f"{base}/api/municipios/3550308/estabelecimentos", f"{base}/api/fontes"]
        try:
            for v in httpx.get(f"{base}/api/vagas?tamanho=100", timeout=5).json()["itens"][: limite_detalhes * 3]:
                rotas["api_soa"].append(f"{base}/api/vagas/{v['id']}")
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            pass
    return rotas


def auditar(
    app: Path | None = None,
    api_csharp: str | None = None,
    api_soa: str | None = None,
    bancos: dict[str, Path] | None = None,
    logs: dict[str, list[Path]] | None = None,
    motor: MotorPII | None = None,
) -> Auditoria:
    motor = motor or MotorPII()
    falhas: list[Falha] = []
    controles: list[dict] = []
    fontes: dict[str, str] = {}

    if app:
        try:
            rel = analisar_app(app)
            fs, cs = falhas_do_taint(rel)
            falhas += fs
            controles += cs
            fontes["taint_app"] = f"{rel['arquivos_analisados']} arquivos, {rel['funcoes_com_resumo']} funções, {rel['resumo']['violacoes']} violações"
        except TaintIndisponivel as e:
            fontes["taint_app"] = f"não rodou: {e}"
        falhas += falhas_do_repositorio(motor, app, "app")
        fontes["repositorio_app"] = "varrido"

    rotas = rotas_padrao(api_csharp, api_soa)
    if rotas:
        fs, est = falhas_das_respostas(motor, rotas)
        falhas += fs
        fontes.update({f"respostas_{k}": v for k, v in est.items()})
    if bancos:
        fs, est = falhas_dos_bancos(motor, bancos)
        falhas += fs
        fontes.update(est)
    if logs:
        fs, est = falhas_dos_logs(motor, logs)
        falhas += fs
        fontes.update(est)

    for f in falhas:
        f.calcular_pontos()
    falhas.sort(key=lambda f: -f.pontos)

    aud = Auditoria(quando=datetime.now(timezone.utc).isoformat(timespec="seconds"), falhas=falhas, controles=controles, fontes=fontes)
    total = sum(f.pontos for f in falhas)
    aud.indice = indice_risco(total, escala=60)
    aud.nivel = nivel_de(aud.indice)
    for comp in ("app", "api_csharp", "api_soa"):
        pts = sum(f.pontos for f in falhas if f.componente == comp)
        ind = indice_risco(pts, escala=30)
        aud.por_componente[comp] = {"indice": ind, "nivel": nivel_de(ind), "falhas": sum(1 for f in falhas if f.componente == comp)}
    return aud


def salvar(aud: Auditoria, pasta: Path) -> Path:
    pasta.mkdir(parents=True, exist_ok=True)
    destino = pasta / "auditoria.json"
    destino.write_text(json.dumps(aud.como_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    historico = pasta / "historico.json"
    linhas = json.loads(historico.read_text(encoding="utf-8")) if historico.exists() else []
    linhas.append({"quando": aud.quando, "indice": aud.indice, "falhas": len(aud.falhas)})
    historico.write_text(json.dumps(linhas[-50:], ensure_ascii=False, indent=2), encoding="utf-8")
    return destino
