"""Tests de l'arithmétique : tables, NTT, multiplication."""

import random

from mlkem.arith import GAMMAS, ZETAS, base_case_multiply, bitrev7, multiply_ntts, ntt, ntt_inv
from mlkem.params import N, Q


def rand_poly(rng):
    return [rng.randrange(Q) for _ in range(N)]


def naive_mul(a, b):
    """Produit naïf modulo X^256 + 1 (X^256 = -1)."""
    c = [0] * N
    for i in range(N):
        for j in range(N):
            k = i + j
            if k < N:
                c[k] += a[i] * b[j]
            else:
                c[k - N] -= a[i] * b[j]
    return [x % Q for x in c]


def test_bitrev7():
    assert bitrev7(0) == 0 and bitrev7(1) == 64 and bitrev7(64) == 1 and bitrev7(127) == 127
    assert sorted(bitrev7(i) for i in range(128)) == list(range(128))


def test_tables():
    assert len(ZETAS) == len(GAMMAS) == 128
    assert ZETAS[0] == 1
    assert ZETAS[1] == pow(17, 64, Q)
    # ζ est d'ordre 256 : ζ^128 = -1 mod q
    assert pow(17, 128, Q) == Q - 1 and pow(17, 256, Q) == 1
    assert all(0 < g < Q for g in GAMMAS)
    # γ_i² = ζ^(2(2·BitRev7(i)+1)) = ζ^(4·BitRev7(i)+2)
    assert all(GAMMAS[i] == pow(17, 2 * bitrev7(i) + 1, Q) for i in range(128))


def test_ntt_roundtrip():
    rng = random.Random(1)
    for _ in range(10):
        f = rand_poly(rng)
        assert ntt_inv(ntt(f)) == f
        assert ntt(ntt_inv(f)) == f


def test_ntt_does_not_mutate_input():
    f = list(range(N))
    copy = list(f)
    ntt(f)
    assert f == copy


def test_multiply_matches_schoolbook():
    rng = random.Random(2)
    for _ in range(3):
        a, b = rand_poly(rng), rand_poly(rng)
        assert ntt_inv(multiply_ntts(ntt(a), ntt(b))) == naive_mul(a, b)


def test_base_case_multiply():
    # (1 + 0X)(b0 + b1X) = b0 + b1X
    assert base_case_multiply(1, 0, 5, 7, 123) == (5, 7)
    # X · X = γ
    assert base_case_multiply(0, 1, 0, 1, 123) == (123, 0)
