"""Motor de PII: exemplos do mundo do Aquenda e propriedades (Hypothesis) sobre os validadores."""

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aquenda_cyber.pii import MotorPII, Sensibilidade
from aquenda_cyber.pii.validadores import cns_valido, cpf_valido, gerar_cns_definitivo, gerar_dv_cpf, luhn_valido

motor = MotorPII()


def regras(texto: str) -> list[str]:
    return [a.regra for a in motor.encontrar(texto)]


# ---------------------------------------------------------------- propriedades

base9 = st.text(alphabet="0123456789", min_size=9, max_size=9).filter(lambda s: len(set(s)) > 1)


@given(base9)
def test_todo_cpf_com_dv_certo_e_detectado_em_qualquer_formato(b):
    cpf = gerar_dv_cpf(b)
    assert cpf_valido(cpf)
    formatos = [cpf, f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}", " ".join(cpf), f"{cpf[:3]} {cpf[3:6]} {cpf[6:9]} {cpf[9:]}"]
    for f in formatos:
        assert "cpf" in regras(f"o cpf é {f}."), f


@given(base9, st.sampled_from([9, 10]), st.integers(min_value=1, max_value=9))
def test_trocar_um_digito_verificador_sempre_quebra_a_validacao(b, pos, delta):
    cpf = gerar_dv_cpf(b)
    errado = cpf[:pos] + str((int(cpf[pos]) + delta) % 10) + cpf[pos + 1 :]
    assert not cpf_valido(errado)


def test_limite_do_proprio_cpf_achado_pelo_hypothesis():
    # Trocar um dígito da BASE pode gerar outro CPF válido: o cálculo junta os restos 10 e 0 no
    # mesmo verificador. Por isso o motor não confia só no dígito: soma o contexto ("cpf").
    original = gerar_dv_cpf("550552303")
    vizinho = "6" + original[1:]
    assert cpf_valido(original) and cpf_valido(vizinho)


@given(st.sampled_from("12"), st.text(alphabet="0123456789", min_size=10, max_size=10))
def test_cns_gerado_pelo_algoritmo_do_datasus_e_valido(inicio, resto):
    assert cns_valido(gerar_cns_definitivo(inicio + resto))


@settings(max_examples=200)
@given(st.text(max_size=300))
def test_redigir_nunca_deixa_cpf_valido_para_tras(texto):
    redigido = motor.redigir(texto)
    for a in motor.encontrar(redigido):
        assert a.regra != "cpf"


@settings(max_examples=200)
@given(st.text(max_size=200))
def test_posicoes_sempre_dentro_do_texto(texto):
    for a in motor.encontrar(texto):
        assert 0 <= a.inicio < a.fim <= len(texto)


# ---------------------------------------------------------------- documentos

CPF = "529.982.247-25"


def test_cpf_em_varios_disfarces():
    assert regras(f"CPF {CPF}") == ["cpf"]
    assert regras("cpf 5 2 9 9 8 2 2 4 7 2 5") == ["cpf"]
    assert regras("CPF: ５２９.９８２.２４７-２５") == ["cpf"]  # dígitos largos
    assert regras("cpf 529.98​2.247-25") == ["cpf"]  # caractere invisível no meio


def test_sequencia_parecida_com_cpf_mas_invalida_nao_e_cpf():
    assert regras("protocolo 123.456.789-00") == []
    assert regras("11111111111") == []


def test_cpf_mascarado_mostra_so_o_final():
    a = motor.encontrar(f"cpf {CPF}")[0]
    assert a.mascarado == "•••.•••.•••-25"
    assert a.sensibilidade is Sensibilidade.PESSOAL
    assert motor.redigir(f"meu cpf {CPF}") == "meu cpf [CPF]"


def test_cartao_sus_e_dado_sensivel():
    cns = gerar_cns_definitivo("12345678901")
    achados = motor.encontrar(f"Cartão SUS {cns[:3]} {cns[3:7]} {cns[7:11]} {cns[11:]}")
    assert [a.regra for a in achados] == ["cns"]
    assert achados[0].sensibilidade is Sensibilidade.SENSIVEL


def test_rg_precisa_da_palavra_rg():
    assert regras("RG 12.345.678-9") == ["rg"]
    assert regras("pedido 12.345.678-9") == []


def test_cartao_de_credito_passa_no_luhn():
    assert luhn_valido("4111 1111 1111 1111")
    assert "cartao_credito" in regras("cartão 4111 1111 1111 1111")


# ---------------------------------------------------------------- contato e lugar


def test_telefone_com_ddd_valido_e_sem():
    assert regras("me chama no (11) 98765-4321") == ["telefone"]
    assert regras("+55 21 3456-7890") == ["telefone"]
    assert regras("código (10) 98765-4321") == []  # DDD 10 não existe


def test_email():
    a = motor.encontrar("escreve pra fulana.silva@gmail.com")[0]
    assert a.regra == "email" and a.mascarado == "f" + "•" * 11 + "@gmail.com"


def test_endereco_so_quando_e_onde_a_pessoa_mora():
    assert regras("moro na Rua das Flores, 120") == ["endereco"]
    # endereço de serviço público (Centro de Referência) não é dado pessoal
    assert regras("O Centro de Referência fica na R. Maj. Sertório, 292") == []


def test_coordenada_precisa_e_a_aproximada_do_app():
    assert regras("estou em -23.543129,-46.643012") == ["coordenada_precisa"]
    assert regras("lat=-23.5431&lon=-46.6430") == []  # 4 casas: o que o app manda de propósito


def test_data_de_nascimento():
    assert regras("nasci em 14/02/1999") == ["data_nascimento"]


# ---------------------------------------------------------------- credenciais


def test_senha_e_pin():
    assert regras("senha: Lua2580!") == ["senha"]
    assert regras('{"pin": "2580"}') == ["senha"]
    a = motor.encontrar("senha=Lua2580!")[0]
    assert a.mascarado == "•" * len("Lua2580!")


def test_placeholder_de_senha_nao_e_senha():
    assert regras("senha: ********") == []
    assert regras("password=${DB_PASSWORD}") == []
    assert regras("senha: <sua senha>") == []


def test_tokens_e_chaves():
    assert regras("x-api-key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123") == ["token"]
    assert regras("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789") == ["token"]
    assert regras("X-Chave-Operador: 9f8e7d6c5b4a3f2e1d0c9b8a") == ["token"]
    assert regras("app_key=3c1f0a9be27d4f88a6c2d1e0f9b8a7c6") == ["token"]
    assert regras("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmn") == ["token"]


def test_nome_de_variavel_nao_e_token():
    assert regras("const token = tokenHash") == []
    assert regras("token: participanteToken") == []


# ---------------------------------------------------------------- saúde (sensível)


@pytest.mark.parametrize(
    "texto",
    [
        "Tomo 2 mg de estradiol todo dia",
        "aplico cipionato de testosterona 1 ampola a cada 21 dias",
        "faço PrEP desde março",
        "fui diagnosticada com HIV",
        "meu laudo psiquiátrico saiu",
        "laudo CID-10 F64.0",
        "estou com depressão",
    ],
)
def test_saude_ligada_a_pessoa_e_dado_sensivel(texto):
    achados = motor.encontrar(texto)
    assert achados and all(a.sensibilidade is Sensibilidade.SENSIVEL for a in achados)
    assert {a.regra for a in achados} == {"saude"}


@pytest.mark.parametrize(
    "texto",
    [
        "A UBS República oferece hormonização pela Rede SAMPA Trans",
        "O CTA faz testagem de HIV e sífilis de graça",
        "Ambulatório e hormônio (habilitação 30.02)",
        "Ninguém aqui indica dose: isso é com a equipe de saúde.",
        # falsos positivos reais achados na auditoria das vagas da Gupy:
        "Preparar o paciente para o atendimento; preparar modelos em gesso",
        "Atender pacientes do CAPS utilizando procedimentos específicos",
    ],
)
def test_saude_como_servico_publico_nao_e_dado_pessoal(texto):
    assert "saude" not in regras(texto)


# ---------------------------------------------------------------- identidade


def test_nome_de_registro_e_mascarado_letra_a_letra():
    a = [x for x in motor.encontrar("Meu nome de registro é João Carlos da Silva") if x.regra == "nome_registro"][0]
    assert a.mascarado == "J••• C••••• d• S••••"
    assert a.sensibilidade is Sensibilidade.SENSIVEL
    assert "nome_registro" in regras("no RG ainda consta Marcos Paulo")
    assert "nome_registro" in regras("antes eu me chamava Pedro")


def test_identidade_em_primeira_pessoa():
    assert regras("eu sou travesti e moro no centro") == ["identidade_genero_orientacao"]
    assert regras("A sala é para pessoas trans e travestis") == []


# ---------------------------------------------------------------- JSON e combinação


def test_json_pelo_nome_do_campo_e_pelo_valor():
    dado = {
        "lembrete": {"titulo": "meu remédio", "anotacao": "tomo 2 mg de estradiol", "pin": "2580"},
        "usuario": {"cpf": "52998224725", "id": 7, "tokenHash": "ABCDEF0123456789ABCDEF0123456789"},
        "servico": {"nome": "UBS República", "atendimentos": ["Hormonizacao"]},
    }
    achados = motor.varrer_estrutura(dado)
    caminhos = {(a.regra, a.origem) for a in achados}
    assert ("saude", "$.lembrete.anotacao") in caminhos
    assert ("pin", "$.lembrete.pin") in caminhos
    assert ("cpf", "$.usuario.cpf") in caminhos
    assert all("tokenHash" not in o for _, o in caminhos)  # hash não é segredo
    assert all("servico" not in o for _, o in caminhos)


def test_varios_dados_na_mesma_mensagem_sem_sobreposicao():
    texto = f"cpf {CPF}, celular 11987654321, senha: Lua2580!, tomo 2 mg de estradiol"
    rs = regras(texto)
    assert rs == ["cpf", "telefone", "senha", "saude"]
    assert json.dumps([a.como_dict() for a in motor.encontrar(texto)], ensure_ascii=False)
