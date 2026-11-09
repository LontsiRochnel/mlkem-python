"""Arithmétique modulo q et transformée NTT.

Le module réalise l'arithmétique sur les polynômes modulo q = 3329, avec la
transformée de Number Theoretic Transform (NTT) utilisée dans le cadre d'un
implémentation pédagogique de ML-KEM.
"""

from __future__ import annotations

from .params import N, Q, ZETA


def reduce_q(value: int) -> int:
    """Réduit une valeur dans l'intervalle [0, q-1]."""
    return value % Q


def ntt(poly: list[int]) -> list[int]:
    """Applique la NTT sans utiliser d'extension externe.

    Args:
        poly (list[int]): coefficients du polynôme.

    Returns:
        list[int]: polynôme transformé.

    Correspondance FIPS 203 : NTT, TODO(verifier).
    """
    a = [reduce_q(x) for x in poly]
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    size = 2
    while size <= n:
        half = size >> 1
        wlen = pow(ZETA, (Q - 1) // size, Q)
        for i in range(0, n, size):
            w = 1
            for j in range(i, i + half):
                u = a[j]
                v = (a[j + half] * w) % Q
                a[j] = (u + v) % Q
                a[j + half] = (u - v) % Q
                w = (w * wlen) % Q
        size <<= 1
    return a


def ntt_inverse(poly: list[int]) -> list[int]:
    """Applique la NTT inverse.

    Args:
        poly (list[int]): coefficients du domaine NTT.

    Returns:
        list[int]: polynôme dans le domaine temporel.

    Correspondance FIPS 203 : NTT inverse, TODO(verifier).
    """
    a = [reduce_q(x) for x in poly]
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    size = 2
    while size <= n:
        half = size >> 1
        wlen = pow(pow(ZETA, -1, Q), (Q - 1) // size, Q)
        for i in range(0, n, size):
            w = 1
            for j in range(i, i + half):
                u = a[j]
                v = (a[j + half] * w) % Q
                a[j] = (u + v) % Q
                a[j + half] = (u - v) % Q
                w = (w * wlen) % Q
        size <<= 1

    inv_n = pow(n, -1, Q)
    return [reduce_q(x * inv_n) for x in a]


def pointwise_multiply(a: list[int], b: list[int]) -> list[int]:
    """Multiplie deux polynômes dans le domaine NTT."""
    if len(a) != len(b):
        raise ValueError(
            "longueurs incompatibles pour la multiplication point par point"
        )
    return [reduce_q(x * y) % Q for x, y in zip(a, b)]
