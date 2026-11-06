"""Pre-commit: barra segredo e dado pessoal nas linhas novas, e deixa código e amostras marcadas passarem."""

import subprocess
from pathlib import Path

import pytest

from aquenda_cyber.hook import instalar, verificar


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    return tmp_path


def stage(repo: Path, nome: str, conteudo: str) -> None:
    (repo / nome).parent.mkdir(parents=True, exist_ok=True)
    (repo / nome).write_text(conteudo, encoding="utf-8")
    subprocess.run(["git", "add", nome], cwd=repo, check=True)


def test_barra_chave_de_api_em_codigo(repo):
    stage(repo, "src/config.ts", 'export const CHAVE = "sk-ant-api03-Zx8Qm2Lk9Pw4Rt7Yv1Bn6Hc3Jd5Fg0Ks";\n')
    b = verificar(repo)
    assert [(x.arquivo, x.linha) for x in b] == [("src/config.ts", 1)]
    assert "Zx8Qm2" not in str(b[0])  # a mensagem mostra só o mascarado


def test_barra_cpf_e_saude_em_arquivo_de_dados(repo):
    stage(repo, "seed/pessoas.json", '{"nome": "Bia", "cpf": "529.982.247-25"}\n{"obs": "tomo estradiol 2mg"}\n')
    assert {x.dado for x in verificar(repo)} == {"CPF", "Dado de saúde"}


def test_codigo_que_fala_de_cpf_passa(repo):
    stage(repo, "src/validar.ts", "export function cpfValido(cpf: string) { return cpf.length === 11; }\nconst senha = lerSenha();\n")
    assert verificar(repo) == []


def test_amostra_de_teste_e_marcador_passam(repo):
    stage(repo, "tests/amostras.json", '{"cpf": "529.982.247-25"}\n')
    stage(repo, "docs/exemplo.txt", "CPF 529.982.247-25 aquenda-pii: ok\n")
    assert verificar(repo) == []


def test_lista_de_permitidos(repo):
    stage(repo, ".aquenda-pii-permitidos", "docs/evidencias/*\n")
    stage(repo, "docs/evidencias/demo.txt", "CPF 529.982.247-25\n")
    assert verificar(repo) == []


def test_so_as_linhas_novas_contam(repo):
    stage(repo, "dados.csv", "cpf\n529.982.247-25\n")
    subprocess.run(["git", "commit", "-qm", "antigo", "--no-verify"], cwd=repo, check=True)
    stage(repo, "dados.csv", "cpf\n529.982.247-25\nlinha nova sem dado\n")
    assert verificar(repo) == []


def test_hook_instalado_barra_o_commit_de_verdade(repo):
    instalar(repo)
    stage(repo, ".env", "ANTHROPIC_API_KEY=sk-ant-api03-Zx8Qm2Lk9Pw4Rt7Yv1Bn6Hc3Jd5Fg0Ks\n")
    r = subprocess.run(["git", "commit", "-qm", "chave"], cwd=repo, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode != 0
    assert "Commit barrado pelo Aquenda" in r.stderr
    assert subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True).returncode != 0  # nada foi commitado


def test_senha_literal_em_codigo_e_barrada(repo):
    stage(repo, "src/db.ts", 'const senha = "Kiwi#2026x";\n')
    assert [x.dado for x in verificar(repo)] == ["Senha ou PIN"]
