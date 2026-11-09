"""Échantillonnage des polynômes et fonctions de dérivation.

Le module encapsule les fonctions de génération pseudo-aléatoire et les
échantillonnages utilisés dans le mécanisme K-PKE puis ML-KEM.
"""

from __future__ import annotations

import hashlib

from .params import N, Q


def XOF(seed: bytes, length: int, domain: bytes = b"") -> bytes:
    """Renvoie une sortie SHAKE128 de longueur demandée.

    Args:
        seed (bytes): graine de départ.
        length (int): longueur demandée en octets.
        domain (bytes): information de domaine supplémentaire.

    Returns:
        bytes: sortie pseudo-aléatoire.

    Correspondance FIPS 203 : SHAKE128 / XOF, TODO(verifier).
    """
    return hashlib.shake_128(seed + domain).digest(length)


def PRF(seed: bytes, length: int, nonce: int = 0) -> bytes:
    """Renvoie une sortie SHAKE256 de longueur demandée.

    Args:
        seed (bytes): graine de départ.
        length (int): longueur demandée en octets.
        nonce (int): nonce comme entier.

    Returns:
        bytes: sortie pseudo-aléatoire.

    Correspondance FIPS 203 : PRF, TODO(verifier).
    """
    return hashlib.shake_256(seed + nonce.to_bytes(4, "little")).digest(length)


def SampleNTT(seed: bytes) -> list[int]:
    """Échantillonne un polynôme de longueur ``N`` dans le domaine NTT.

    Args:
        seed (bytes): graine utilisable par SHAKE128.

    Returns:
        list[int]: coefficients du polynôme, réduits modulo ``q``.

    Correspondance FIPS 203 : SampleNTT, TODO(verifier).
    """
    out: list[int] = []
    data = XOF(seed, 3 * N)
    for idx in range(N):
        chunk = data[3 * idx : 3 * idx + 3]
        value = int.from_bytes(chunk, "little") % Q
        out.append(value)
    return out


def SamplePolyCBD_η(seed: bytes, eta: int, length: int = N) -> list[int]:
    """Échantillonne un polynôme à partir d'un CBD (centered binomial distribution).

    Args:
        seed (bytes): graine.
        eta (int): paramètre du CBD.
        length (int): cardinal du polynôme.

    Returns:
        list[int]: coefficients réduits modulo ``q``.

    Correspondance FIPS 203 : SamplePolyCBD_η, TODO(verifier).
    """
    if eta not in (2, 3):
        raise ValueError("eta supporté uniquement pour les valeurs 2 et 3")

    values: list[int] = []
    for idx in range(length):
        digest = hashlib.shake_256(seed + idx.to_bytes(2, "little")).digest(8)
        word = int.from_bytes(digest, "little")
        a = (word & ((1 << eta) - 1)).bit_count()
        b = ((word >> eta) & ((1 << eta) - 1)).bit_count()
        values.append((a - b) % Q)
    return values
