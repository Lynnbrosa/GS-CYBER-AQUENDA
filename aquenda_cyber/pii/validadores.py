"""Validação matemática dos documentos: separa número de verdade de sequência qualquer."""

from __future__ import annotations

from .normalizacao import so_digitos

# DDDs válidos no Brasil (Anatel). Telefone com DDD fora da lista não é telefone brasileiro.
DDDS = {
    11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 24, 27, 28, 31, 32, 33, 34, 35, 37, 38,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 51, 53, 54, 55, 61, 62, 63, 64, 65, 66, 67, 68, 69,
    71, 73, 74, 75, 77, 79, 81, 82, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99,
}


def cpf_valido(texto: str) -> bool:
    d = so_digitos(texto)
    if len(d) != 11 or d == d[0] * 11:
        return False
    nums = [int(c) for c in d]
    for pos in (9, 10):
        soma = sum(n * (pos + 1 - i) for i, n in enumerate(nums[:pos]))
        dv = (soma * 10) % 11 % 10
        if dv != nums[pos]:
            return False
    return True


def gerar_dv_cpf(base9: str) -> str:
    """Completa 9 dígitos com os 2 verificadores (usado nos testes de propriedade)."""
    nums = [int(c) for c in base9]
    for pos in (9, 10):
        soma = sum(n * (pos + 1 - i) for i, n in enumerate(nums[:pos]))
        nums.append((soma * 10) % 11 % 10)
    return "".join(map(str, nums))


def cns_valido(texto: str) -> bool:
    """Cartão Nacional de Saúde (15 dígitos). Definitivo começa com 1 ou 2; provisório com 7, 8 ou 9.
    Nos dois casos a soma ponderada (pesos 15..1) tem que ser múltipla de 11."""
    d = so_digitos(texto)
    if len(d) != 15 or d[0] not in "12789":
        return False
    soma = sum(int(c) * (15 - i) for i, c in enumerate(d))
    return soma % 11 == 0


def gerar_cns_definitivo(pis11: str) -> str:
    """Monta um CNS definitivo a partir de 11 dígitos começando com 1 ou 2 (algoritmo do DATASUS)."""
    soma = sum(int(c) * (15 - i) for i, c in enumerate(pis11))
    resto = soma % 11
    dv = 11 - resto
    if dv == 11:
        dv = 0
    if dv == 10:
        soma += 2
        resto = soma % 11
        dv = 11 - resto
        return f"{pis11}001{dv}"
    return f"{pis11}000{dv}"


def luhn_valido(texto: str) -> bool:
    d = so_digitos(texto)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def telefone_br_valido(texto: str) -> bool:
    d = so_digitos(texto)
    if d.startswith("55") and len(d) in (12, 13):
        d = d[2:]
    if len(d) not in (10, 11):
        return False
    if int(d[:2]) not in DDDS:
        return False
    numero = d[2:]
    if len(numero) == 9:
        return numero[0] == "9"  # celular: 9 na frente
    return numero[0] in "2345"  # fixo


def entropia_shannon(texto: str) -> float:
    """Bits por caractere. Senha e token aleatório ficam acima de ~3,5; palavras, abaixo de ~3."""
    import math

    if not texto:
        return 0.0
    contagem: dict[str, int] = {}
    for c in texto:
        contagem[c] = contagem.get(c, 0) + 1
    n = len(texto)
    return -sum(v / n * math.log2(v / n) for v in contagem.values())
