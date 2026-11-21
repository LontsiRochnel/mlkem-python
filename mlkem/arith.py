"""Arithmétique dans R_q et dans T_q (domaine NTT).

Rôle dans l'architecture : brique mathématique utilisée par K-PKE.
Les polynômes sont des listes de 256 entiers dans [0, q). Ce module
calcule *lui-même* les tables de zetas et de gammas à partir des
formules de FIPS 203 (aucune table recopiée) :

* zetas[i]  = ζ^BitRev7(i) mod q, i = 0..127   (NTT et NTT inverse)
* gammas[i] = ζ^(2·BitRev7(i)+1) mod q          (BaseCaseMultiply)

Le test ``tests/test_arith.py`` vérifie la cohérence des tables : NTT puis
NTT inverse donne l'identité, et le produit dans le domaine NTT égale le
produit naïf modulo X^256 + 1.
"""

from .params import N, Q, ZETA


def bitrev7(i: int) -> int:
    """Inverse les 7 bits de poids faible de ``i`` (BitRev7).

    Args:
        i: Entier dans [0, 128).

    Returns:
        L'entier dont l'écriture binaire sur 7 bits est celle de ``i``
        lue à l'envers.
    """
    return int(f"{i:07b}"[::-1], 2)


ZETAS = tuple(pow(ZETA, bitrev7(i), Q) for i in range(128))
"""Table ζ^BitRev7(i) mod q, i = 0..127, calculée (non recopiée)."""

GAMMAS = tuple(pow(ZETA, 2 * bitrev7(i) + 1, Q) for i in range(128))
"""Table ζ^(2·BitRev7(i)+1) mod q, i = 0..127, calculée (non recopiée)."""

N_INV = pow(128, -1, Q)
"""Inverse de 128 modulo q (facteur final de la NTT inverse, 3303)."""


def poly_add(f: list[int], g: list[int]) -> list[int]:
    """Additionne deux polynômes coefficient par coefficient modulo q.

    Args:
        f: Polynôme (256 entiers dans [0, q)).
        g: Polynôme (256 entiers dans [0, q)).

    Returns:
        Le polynôme f + g (coefficients dans [0, q)).
    """
    return [(a + b) % Q for a, b in zip(f, g)]


def poly_sub(f: list[int], g: list[int]) -> list[int]:
    """Soustrait deux polynômes coefficient par coefficient modulo q.

    Args:
        f: Polynôme (256 entiers dans [0, q)).
        g: Polynôme (256 entiers dans [0, q)).

    Returns:
        Le polynôme f - g (coefficients dans [0, q)).
    """
    return [(a - b) % Q for a, b in zip(f, g)]


def ntt(f: list[int]) -> list[int]:
    """Transformée en nombres théoriques (NTT) d'un polynôme.

    Implémente l'algorithme NTT de FIPS 203 : papillons de Cooley-Tukey,
    longueurs 128, 64, ..., 2 (la dernière couche de longueur 1 n'existe
    pas : on obtient 128 polynômes de degré 1 et non 256 évaluations).

    Args:
        f: Polynôme de R_q (256 entiers dans [0, q)).

    Returns:
        Une *nouvelle* liste de 256 entiers : f̂ dans T_q.
    """
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                # t = ζ · f[j+len] ; réduction modulo q à chaque produit
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def ntt_inv(f_hat: list[int]) -> list[int]:
    """NTT inverse : repasse de T_q à R_q.

    Implémente l'algorithme NTT inverse de FIPS 203 : papillons de
    Gentleman-Sande, longueurs 2, 4, ..., 128, zetas parcourus à
    l'envers, puis multiplication de tous les coefficients par 128^{-1}.

    Args:
        f_hat: Représentation NTT (256 entiers dans [0, q)).

    Returns:
        Une *nouvelle* liste de 256 entiers : le polynôme f de R_q.
    """
    f = list(f_hat)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    # facteur 128^{-1} : compense les 7 couches de doublement
    return [x * N_INV % Q for x in f]


def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> tuple[int, int]:
    """Produit de (a0 + a1·X) par (b0 + b1·X) modulo X² − γ.

    Implémente BaseCaseMultiply de FIPS 203.

    Args:
        a0: Premier coefficient du premier facteur, dans [0, q).
        a1: Second coefficient du premier facteur, dans [0, q).
        b0: Premier coefficient du second facteur, dans [0, q).
        b1: Second coefficient du second facteur, dans [0, q).
        gamma: Racine γ = ζ^(2·BitRev7(i)+1) mod q.

    Returns:
        Le couple (c0, c1) de coefficients du produit, dans [0, q).
    """
    c0 = (a0 * b0 + a1 * b1 % Q * gamma) % Q  # X² se réduit en γ
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1


def multiply_ntts(f_hat: list[int], g_hat: list[int]) -> list[int]:
    """Produit de deux polynômes dans le domaine NTT.

    Implémente MultiplyNTTs de FIPS 203 : 128 produits de degré 1,
    chacun modulo X² − γ_i avec γ_i = ζ^(2·BitRev7(i)+1).

    Args:
        f_hat: Représentation NTT (256 entiers dans [0, q)).
        g_hat: Représentation NTT (256 entiers dans [0, q)).

    Returns:
        La représentation NTT du produit (256 entiers dans [0, q)).
    """
    h = [0] * N
    for i in range(128):
        h[2 * i], h[2 * i + 1] = base_case_multiply(
            f_hat[2 * i], f_hat[2 * i + 1], g_hat[2 * i], g_hat[2 * i + 1], GAMMAS[i]
        )
    return h
