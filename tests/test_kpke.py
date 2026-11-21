"""Tests de K-PKE seul."""

import os

import pytest

from mlkem.errors import InvalidCiphertextLengthError, InvalidInputLengthError, InvalidKeyLengthError
from mlkem.kpke import kpke_decrypt, kpke_encrypt, kpke_keygen
from mlkem.params import VARIANTS

NAMES = list(VARIANTS)


@pytest.mark.parametrize("name", NAMES)
def test_encrypt_decrypt(name):
    p = VARIANTS[name]
    ek, dk = kpke_keygen(os.urandom(32), p)
    assert len(ek) == p.ek_size and len(dk) == p.dk_pke_size
    for m in (os.urandom(32), b"\x00" * 32, b"\xff" * 32):
        c = kpke_encrypt(ek, m, os.urandom(32), p)
        assert len(c) == p.c_size
        assert kpke_decrypt(dk, c, p) == m


def test_deterministic():
    d, r, m = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
    ek, dk = kpke_keygen(d, "ML-KEM-512")
    assert (ek, dk) == kpke_keygen(d, "ML-KEM-512")
    assert kpke_encrypt(ek, m, r, "ML-KEM-512") == kpke_encrypt(ek, m, r, "ML-KEM-512")


def test_invalid_lengths():
    ek, dk = kpke_keygen(b"\x00" * 32, "ML-KEM-512")
    with pytest.raises(InvalidInputLengthError):
        kpke_keygen(b"\x00" * 31, "ML-KEM-512")
    with pytest.raises(InvalidInputLengthError):
        kpke_encrypt(ek, b"\x00" * 31, b"\x00" * 32, "ML-KEM-512")
    with pytest.raises(InvalidKeyLengthError):
        kpke_encrypt(ek[:-1], b"\x00" * 32, b"\x00" * 32, "ML-KEM-512")
    with pytest.raises(InvalidCiphertextLengthError):
        kpke_decrypt(dk, b"\x00" * 10, "ML-KEM-512")
