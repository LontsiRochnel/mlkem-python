"""Encodage et décodage des coefficients et des octets.

Le module fournit les fonctions d'encodage de polynômes et de compression,
cohérentes avec l'architecture ML-KEM et son usage pédagogique.
"""

from __future__ import annotations

from typing import Iterable

from .params import Q


def BitsToBytes(bits: bytes) -> bytes:
    """Convertit une suite de bits 0/1 en octets."""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def BytesToBits(data: bytes) -> bytes:
    """Convertit une séquence d'octets en séquence de bits."""
    out = bytearray()
    for byte in data:
        for bit_index in range(8):
            out.append((byte >> bit_index) & 1)
    return bytes(out)


def ByteEncode_d(poly: Iterable[int], d: int) -> bytes:
    """Encode un polynôme en octets sur ``d`` bits par coefficient.

    Args:
        poly (Iterable[int]): coefficients du polynôme.
        d (int): nombre de bits par coefficient.

    Returns:
        bytes: représentation byte-packed des coefficients.

    Correspondance FIPS 203 : ByteEncode_d, TODO(verifier).
    """
    if d <= 0:
        raise ValueError("d doit être strictement positif")
    out = bytearray()
    for value in poly:
        v = int(value) % Q
        bits = format(v, f"0{d}b")
        for ch in bits:
            out.append(ord(ch) - 48)
    return BitsToBytes(bytes(out))


def ByteDecode_d(data: bytes, d: int, length: int) -> list[int]:
    """Decode des octets vers une liste de coefficients sur ``d`` bits.

    Args:
        data (bytes): octets encodés.
        d (int): nombre de bits par coefficient.
        length (int): nombre attendu de coefficients.

    Returns:
        list[int]: coefficients décodés.

    Correspondance FIPS 203 : ByteDecode_d, TODO(verifier).
    """
    if d <= 0:
        raise ValueError("d doit être strictement positif")
    bits = BytesToBits(data)
    values: list[int] = []
    for index in range(length):
        start = index * d
        stop = start + d
        chunk = bits[start:stop]
        if len(chunk) < d:
            break
        value = 0
        for bit in chunk:
            value = (value << 1) | int(bit)
        values.append(value % Q)
    return values


def Compress_d(x: int, d: int) -> int:
    """Compression d'un coefficient sur ``d`` bits.

    Args:
        x (int): coefficient avant compression.
        d (int): nombre de bits.

    Returns:
        int: coefficient compressé.

    Correspondance FIPS 203 : Compress_d, TODO(verifier).
    """
    if d <= 0:
        raise ValueError("d doit être strictement positif")
    x = int(x) % Q
    return min((x * ((1 << d) - 1) + (Q // 2)) // Q, (1 << d) - 1)


def Decompress_d(x: int, d: int) -> int:
    """Décompression d'un coefficient sur ``d`` bits."""
    if d <= 0:
        raise ValueError("d doit être strictement positif")
    x = int(x) % (1 << d)
    return ((x * Q) + (1 << (d - 1))) >> d
