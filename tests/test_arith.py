import pytest

from mlkem.arith import ntt, ntt_inverse


def test_ntt_roundtrip():
    poly = [(i * 19 + 7) % 3329 for i in range(256)]
    recovered = ntt_inverse(ntt(poly))
    assert recovered == poly
