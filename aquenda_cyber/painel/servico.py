"""Painel executivo de Risco Cidadão (FastAPI + uma página HTML).

Dois alvos:
- "prototipo": o Aquenda de verdade (app, API C#, FastAPI, bancos e logs);
- "exemplo": o app de exemplo com vazamentos plantados e um log vulnerável, para mostrar
  o que o painel faz quando acha problema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse

from ..auditoria import Auditoria, Falha, auditar, salvar
from ..ia.remediacao import Tradutor

RAIZ = Path(__file__).resolve().parents[2]
PAGINA = Path(__file__).with_name("pagina.html")


@dataclass
class Configuracao:
    app: Path | None = None
    api_csharp: str | None = None
    api_soa: str | None = None
    bancos: dict[str, Path] = field(default_factory=dict)
    logs: dict[str, list[Path]] = field(default_factory=dict)
    saida: Path = RAIZ / "saida"
    usar_claude: bool | None = None
    alertas_por_auditoria: int = 8


def config_exemplo(base: Configuracao) -> Configuracao:
    return Configuracao(
        app=RAIZ / "taint_ts" / "exemplos" / "vulneravel",
        logs={"api_csharp": [RAIZ / "exemplos" / "logs" / "api-com-vazamento.log"]},
        saida=base.saida,
        usar_claude=base.usar_claude,
        alertas_por_auditoria=base.alertas_por_auditoria,
    )


def rodar(conf: Configuracao, alvo: str) -> dict:
    aud = auditar(app=conf.app, api_csharp=conf.api_csharp, api_soa=conf.api_soa, bancos=conf.bancos or None, logs=conf.logs or None)
    pasta = conf.saida / alvo
    salvar(aud, pasta)
    tradutor = Tradutor(cache=conf.saida / "cache_ia.json", usar_claude=conf.usar_claude)
    alertas = [tradutor.traduzir(f).model_dump() for f in aud.falhas[: conf.alertas_por_auditoria]]
    (pasta / "alertas.json").write_text(json.dumps(alertas, ensure_ascii=False, indent=2), encoding="utf-8")
    return montar_resposta(pasta)


def montar_resposta(pasta: Path) -> dict:
    arq = pasta / "auditoria.json"
    if not arq.exists():
        raise FileNotFoundError(pasta)
    aud = json.loads(arq.read_text(encoding="utf-8"))
    alertas = json.loads((pasta / "alertas.json").read_text(encoding="utf-8")) if (pasta / "alertas.json").exists() else []
    historico = json.loads((pasta / "historico.json").read_text(encoding="utf-8")) if (pasta / "historico.json").exists() else []
    return {"auditoria": aud, "alertas": alertas, "historico": historico}


def criar_app(conf: Configuracao) -> FastAPI:
    app = FastAPI(title="Aquenda · Risco Cidadão", docs_url="/docs")
    confs = {"prototipo": conf, "exemplo": config_exemplo(conf)}

    @app.get("/", response_class=HTMLResponse)
    def pagina() -> str:
        return PAGINA.read_text(encoding="utf-8")

    @app.get("/logo.png")
    def logo() -> FileResponse:
        return FileResponse(Path(__file__).with_name("logo.png"), media_type="image/png")

    @app.get("/api/painel")
    def painel(alvo: str = "prototipo") -> dict:
        if alvo not in confs:
            raise HTTPException(404, "alvo desconhecido")
        try:
            return montar_resposta(conf.saida / alvo)
        except FileNotFoundError:
            return rodar(confs[alvo], alvo)

    @app.post("/api/auditar")
    def auditar_agora(alvo: str = "prototipo") -> dict:
        if alvo not in confs:
            raise HTTPException(404, "alvo desconhecido")
        return rodar(confs[alvo], alvo)

    return app


__all__ = ["Auditoria", "Configuracao", "Falha", "criar_app", "rodar"]
