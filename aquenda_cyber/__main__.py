"""Linha de comando do módulo de segurança do Aquenda.

    python -m aquenda_cyber varrer "texto ou caminho"     # motor de PII
    python -m aquenda_cyber taint ../GS-MOBILE-AQUENDA      # taint analysis do app
    python -m aquenda_cyber auditar [opções]               # auditoria completa + alertas da IA
    python -m aquenda_cyber painel [opções]                # painel de Risco Cidadão em http://localhost:8600
    python -m aquenda_cyber empacotar                      # ZIP da entrega
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

from .pii import MotorPII, resumir
from .pii.motor import iterar_linhas

RAIZ = Path(__file__).resolve().parents[1]


def _opcoes_alvo(p: argparse.ArgumentParser) -> None:
    p.add_argument("--app", type=Path, default=RAIZ.parent / "GS-MOBILE-AQUENDA", help="pasta do app Expo")
    p.add_argument("--api-csharp", default="http://localhost:5000")
    p.add_argument("--api-soa", default="http://localhost:8000")
    p.add_argument("--banco-csharp", type=Path, default=RAIZ.parent / "GS-c--AQUENDA" / "src" / "Aquenda.Api" / "aquenda.db")
    p.add_argument("--banco-soa", type=Path, default=RAIZ.parent / "GS-SOA-AQUENDA" / "aquenda_soa.db")
    p.add_argument("--log-csharp", type=Path, action="append", default=[])
    p.add_argument("--log-soa", type=Path, action="append", default=[])
    p.add_argument("--saida", type=Path, default=RAIZ / "saida")
    p.add_argument("--sem-ia", action="store_true", help="não chama o Claude (usa o tradutor local)")


def _configuracao(a):
    from .painel.servico import Configuracao

    return Configuracao(
        app=a.app if a.app and a.app.exists() else None,
        api_csharp=a.api_csharp or None,
        api_soa=a.api_soa or None,
        bancos={"api_csharp": a.banco_csharp, "api_soa": a.banco_soa},
        logs={"api_csharp": a.log_csharp, "api_soa": a.log_soa},
        saida=a.saida,
        usar_claude=False if a.sem_ia else None,
    )


def cmd_varrer(a) -> int:
    motor = MotorPII()
    alvo = Path(a.alvo)
    if alvo.exists():
        achados = motor.varrer_pasta(alvo) if alvo.is_dir() else motor.varrer_arquivo(alvo)
    else:
        achados = motor.encontrar(a.alvo, "texto")
    if a.json:
        print(json.dumps([x.como_dict() for x in achados], ensure_ascii=False, indent=2))
    else:
        for linha in iterar_linhas(achados):
            print(linha)
        print(f"\n{len(achados)} achado(s): {resumir(achados)}")
        if not alvo.exists():
            print("Redigido:", motor.redigir(a.alvo))
    return 1 if achados else 0


def cmd_taint(a) -> int:
    from .taint import analisar_app

    rel = analisar_app(a.app)
    if a.json:
        print(json.dumps(rel, ensure_ascii=False, indent=2))
        return 2 if rel["resumo"]["violacoes"] else 0
    print(f"{rel['arquivos_analisados']} arquivos, {rel['funcoes_com_resumo']} funções com resumo, ponto fixo em {rel['rodadas_ate_ponto_fixo']} rodadas")
    print(f"{len(rel['fontes'])} fontes de dado sensível encontradas")
    for f in rel["fluxos"]:
        marca = "VIOLAÇÃO " if f["veredito"] == "violacao" else "permitido"
        print(f"  [{marca}] {f['rotulo']:<12} -> {f['sumidouro']:<24} {f['onde']}")
        if f["veredito"] == "violacao":
            for passo in f["trilha"]:
                print(f"               {passo}")
    print(f"\n{rel['resumo']['violacoes']} violação(ões), {rel['resumo']['permitidos']} fluxo(s) permitido(s) pela política")
    return 2 if rel["resumo"]["violacoes"] else 0


def cmd_auditar(a) -> int:
    from .painel.servico import config_exemplo, rodar

    conf = _configuracao(a)
    alvo = "exemplo" if a.exemplo else "prototipo"
    resposta = rodar(config_exemplo(conf) if a.exemplo else conf, alvo)
    aud = resposta["auditoria"]
    print(f"Risco Cidadão: {aud['indice']}/100 ({aud['nivel']})")
    for comp, v in aud["por_componente"].items():
        print(f"  {comp:<11} {v['indice']:>3}  {v['nivel']:<9} {v['falhas']} falha(s)")
    print("\nO que rodou:")
    for k, v in aud["fontes"].items():
        print(f"  {k}: {v}")
    print("\nAlertas:")
    for g in resposta["alertas"]:
        print(f"  [{g['alerta']['gravidade']}] {g['alerta']['titulo']}  ({g['gerado_por']})")
    print(f"\nRelatório em {conf.saida / alvo / 'auditoria.json'}")
    return 0


def cmd_painel(a) -> int:
    import uvicorn

    from .painel.servico import criar_app

    print(f"Painel em http://localhost:{a.porta}")
    uvicorn.run(criar_app(_configuracao(a)), host="127.0.0.1", port=a.porta, log_level="warning")
    return 0


def cmd_empacotar(a) -> int:
    """ZIP da entrega: código do módulo com as regras PII, exemplos, testes e evidências."""
    destino = a.destino or (RAIZ / "dist" / "GS-CYBER-AQUENDA.zip")
    destino.parent.mkdir(parents=True, exist_ok=True)
    incluir = ["aquenda_cyber", "taint_ts", "exemplos", "tests", "docs", "README.md", "requirements.txt", "package.json", "package-lock.json", "pyproject.toml"]
    ignorar = {"__pycache__", "node_modules", ".pytest_cache", ".hypothesis"}
    n = 0
    with zipfile.ZipFile(destino, "w", zipfile.ZIP_DEFLATED) as z:
        for item in incluir:
            caminho = RAIZ / item
            if not caminho.exists():
                continue
            arquivos = [caminho] if caminho.is_file() else [p for p in caminho.rglob("*") if p.is_file()]
            for arq in arquivos:
                if ignorar & set(arq.parts):
                    continue
                z.write(arq, Path("GS-CYBER-AQUENDA") / arq.relative_to(RAIZ))
                n += 1
    print(f"{destino} ({n} arquivos)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aquenda_cyber", description="Segurança e privacidade do Aquenda")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("varrer", help="procura PII num texto, arquivo ou pasta")
    v.add_argument("alvo")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_varrer)

    t = sub.add_parser("taint", help="taint analysis do app")
    t.add_argument("app", type=Path, nargs="?", default=RAIZ.parent / "GS-MOBILE-AQUENDA")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=cmd_taint)

    au = sub.add_parser("auditar", help="auditoria completa e alertas de Risco Cidadão")
    _opcoes_alvo(au)
    au.add_argument("--exemplo", action="store_true", help="audita o exemplo com falhas plantadas")
    au.set_defaults(func=cmd_auditar)

    pa = sub.add_parser("painel", help="painel web de Risco Cidadão")
    _opcoes_alvo(pa)
    pa.add_argument("--porta", type=int, default=8600)
    pa.set_defaults(func=cmd_painel)

    e = sub.add_parser("empacotar", help="gera o ZIP da entrega")
    e.add_argument("--destino", type=Path)
    e.set_defaults(func=cmd_empacotar)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
