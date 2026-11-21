"""Hachages, XOF et échantillonnage (SampleNTT, SamplePolyCBD).

Rôle dans l'architecture : fournit les primitives de hachage de
FIPS 203 (H, G, J, PRF, XOF, toutes via hashlib) et les deux
échantillonneurs : SampleNTT (matrice publique A, par rejet sur un flux
SHAKE128) et SamplePolyCBD_η (bruit, loi binomiale centrée).
"""

import hashlib

from .encoding import bytes_to_bits
from .params import N, Q


def H(x: bytes) -> bytes:
    """H = SHA3-256.

    Args:
        x: Message en octets.

    Returns:
        Condensat de 32 octets.
    """
    return hashlib.sha3_256(x).digest()


def G(x: bytes) -> tuple[bytes, bytes]:
    """G = SHA3-512, coupé en deux moitiés de 32 octets.

    Args:
        x: Message en octets.

    Returns:
        Le couple (a, b) de deux chaînes de 32 octets.
    """
    out = hashlib.sha3_512(x).digest()
    return out[:32], out[32:]


def J(x: bytes) -> bytes:
    """J = SHAKE256 tronqué à 32 octets.

    Args:
        x: Message en octets.

    Returns:
        32 octets.
    """
    return hashlib.shake_256(x).digest(32)


def prf(eta: int, s: bytes, b: int) -> bytes:
    """PRF_η(s, b) = SHAKE256(s || b), sortie de 64·η octets.

    Args:
        eta: Paramètre η (2 ou 3).
        s: Graine de 32 octets.
        b: Compteur (un octet, entier dans [0, 256)).

    Returns:
        64·η octets pseudo-aléatoires.
    """
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def xof_input(rho: bytes, j: int, i: int) -> bytes:
    """Construit l'entrée ρ || j || i du XOF pour A[i][j].

    TODO(verifier) : confirmer dans FIPS 203 l'ordre des deux octets
    d'indices (colonne j puis ligne i).

    Args:
        rho: Graine publique de 32 octets.
        j: Indice de colonne (un octet).
        i: Indice de ligne (un octet).

    Returns:
        34 octets.
    """
    return rho + bytes([j, i])


def sample_ntt(B: bytes) -> list[int]:
    """SampleNTT : échantillonne un polynôme de T_q par rejet.

    Le flux SHAKE128(B) est lu par blocs de 3 octets, qui donnent deux
    candidats de 12 bits ; un candidat n'est retenu que s'il est < q
    (rejet : sinon la distribution ne serait pas uniforme).
    ``hashlib`` ne permet pas de lire un flux par morceaux : on demande
    un flux plus long (recalculé) tant que 256 coefficients manquent.

    Args:
        B: Entrée du XOF, 34 octets (ρ || j || i).

    Returns:
        256 entiers uniformes dans [0, q), vus comme éléments de T_q.
    """
    length = 504  # 3 blocs de 168 octets : suffit presque toujours
    stream = hashlib.shake_128(B).digest(length)
    a: list[int] = []
    pos = 0
    while len(a) < N:
        if pos + 3 > len(stream):
            length *= 2
            stream = hashlib.shake_128(B).digest(length)
        c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3
        d1 = c0 + 256 * (c1 % 16)  # 12 bits : octet 0 + 4 bits bas de l'octet 1
        d2 = c1 // 16 + 16 * c2    # 12 bits : 4 bits hauts de l'octet 1 + octet 2
        if d1 < Q:
            a.append(d1)
        if d2 < Q and len(a) < N:
            a.append(d2)
    return a


def sample_poly_cbd(B: bytes, eta: int) -> list[int]:
    """SamplePolyCBD_η : polynôme à coefficients binomiaux centrés.

    Chaque coefficient vaut (somme de η bits) − (somme de η autres bits),
    réduit modulo q (valeur dans [−η, η]).

    Args:
        B: 64·η octets pseudo-aléatoires (sortie de ``prf``).
        eta: Paramètre η (2 ou 3).

    Returns:
        256 entiers dans [0, q).

    Raises:
        ValueError: Si len(B) != 64·η.
    """
    if len(B) != 64 * eta:
        raise ValueError(f"{64 * eta} octets attendus")
    bits = bytes_to_bits(B)
    f = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        f.append((x - y) % Q)  # % Q ramène les négatifs dans [0, q)
    return f
