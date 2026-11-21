"""Tests des tailles (ek, dk, c, K) des trois variantes."""

import pytest

import mlkem
from mlkem.params import VARIANTS

EXPECTED = {
    "ML-KEM-512": (800, 1632, 768, 32),
    "ML-KEM-768": (1184, 2400, 1088, 32),
    "ML-KEM-1024": (1568, 3168, 1568, 32),
}


@pytest.mark.parametrize("name", list(EXPECTED))
def test_computed_sizes(name):
    p = VARIANTS[name]
    assert (p.ek_size, p.dk_size, p.c_size, p.K_size) == EXPECTED[name]
    assert mlkem.SIZES[name] == EXPECTED[name]


@pytest.mark.parametrize("name", list(EXPECTED))
def test_actual_sizes(name):
    ek_n, dk_n, c_n, K_n = EXPECTED[name]
    ek, dk = mlkem.keygen(name)
    K, c = mlkem.encaps(ek)
    assert (len(ek), len(dk), len(c), len(K)) == (ek_n, dk_n, c_n, K_n)
