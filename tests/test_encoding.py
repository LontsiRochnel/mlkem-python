"""Tests de l'encodage et de la compression."""

import random

import pytest

from mlkem.encoding import (
    bits_to_bytes, byte_decode, byte_encode, bytes_to_bits, compress, decompress,
)
from mlkem.params import N, Q


def test_bits_bytes_roundtrip():
    data = bytes(range(256))
    assert bits_to_bytes(bytes_to_bits(data)) == data
    assert bytes_to_bits(b"\x01") == [1, 0, 0, 0, 0, 0, 0, 0]  # poids faible d'abord
    with pytest.raises(ValueError):
        bits_to_bytes([1, 0, 1])


@pytest.mark.parametrize("d", list(range(1, 13)))
def test_byte_encode_roundtrip(d):
    rng = random.Random(d)
    m = Q if d == 12 else 1 << d
    F = [rng.randrange(m) for _ in range(N)]
    B = byte_encode(F, d)
    assert len(B) == 32 * d
    assert byte_decode(B, d) == F


def test_byte_encode_bounds():
    with pytest.raises(ValueError):
        byte_encode([Q] + [0] * 255, 12)
    with pytest.raises(ValueError):
        byte_encode([16] + [0] * 255, 4)
    with pytest.raises(ValueError):
        byte_decode(b"\x00" * 10, 4)


def test_byte_decode_12_reduces_mod_q():
    B = b"\xff\x0f" + b"\x00" * (384 - 2)  # premier coefficient = 4095
    assert byte_decode(B, 12)[0] == 4095 % Q


@pytest.mark.parametrize("d", [1, 4, 5, 10, 11])
def test_compress_bounds_and_error(d):
    for x in range(Q):
        y = compress(x, d)
        assert 0 <= y < (1 << d)
        # erreur de l'aller-retour <= ⌈q / 2^{d+1}⌋ (distance circulaire)
        diff = abs(decompress(y, d) - x)
        diff = min(diff, Q - diff)
        assert diff <= (Q + (1 << (d + 1)) - 1) // (1 << (d + 1))


@pytest.mark.parametrize("d", [1, 4, 5, 10, 11])
def test_decompress_then_compress_identity(d):
    for y in range(1 << d):
        z = decompress(y, d)
        assert 0 <= z < Q
        assert compress(z, d) == y


def test_compress_1_message_bits():
    assert decompress(0, 1) == 0
    assert decompress(1, 1) == (Q + 1) // 2  # ⌈q/2⌋ = 1665
    assert compress(0, 1) == 0 and compress(1665, 1) == 1
