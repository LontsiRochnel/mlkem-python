"""Tests de l'échantillonnage."""

import hashlib
import random

import pytest

from mlkem.params import N, Q
from mlkem.sampling import G, H, J, prf, sample_ntt, sample_poly_cbd, xof_input


def test_hashes_match_hashlib():
    assert H(b"abc") == hashlib.sha3_256(b"abc").digest()
    a, b = G(b"abc")
    assert a + b == hashlib.sha3_512(b"abc").digest()
    assert J(b"abc") == hashlib.shake_256(b"abc").digest(32)
    assert len(prf(2, b"\x00" * 32, 0)) == 128 and len(prf(3, b"\x00" * 32, 0)) == 192


def test_sample_ntt():
    B = xof_input(b"\x07" * 32, 1, 2)
    assert len(B) == 34
    a = sample_ntt(B)
    assert len(a) == N and all(0 <= x < Q for x in a)
    assert a == sample_ntt(B)  # déterministe
    assert a != sample_ntt(xof_input(b"\x07" * 32, 2, 1))


def test_cbd_known_values():
    f = sample_poly_cbd(b"\x03" * 128, 2)  # octet 0x03 : x=2, y=0 puis x=0, y=0
    assert f[0] == 2 and f[1] == 0 and f[2] == 2
    assert sample_poly_cbd(b"\x00" * 128, 2) == [0] * N
    assert sample_poly_cbd(b"\xff" * 192, 3) == [0] * N  # x = y = η
    g = sample_poly_cbd(b"\x07" + b"\x00" * 191, 3)
    assert g[0] == 3


@pytest.mark.parametrize("eta", [2, 3])
def test_cbd_range(eta):
    rng = random.Random(eta)
    f = sample_poly_cbd(bytes(rng.randrange(256) for _ in range(64 * eta)), eta)
    allowed = {x % Q for x in range(-eta, eta + 1)}
    assert len(f) == N and set(f) <= allowed


def test_cbd_wrong_length():
    with pytest.raises(ValueError):
        sample_poly_cbd(b"\x00" * 100, 2)
