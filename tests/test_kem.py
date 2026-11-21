"""Tests de ML-KEM : aller-retour, rejet implicite, entrées invalides."""

import hashlib
import os

import pytest

import mlkem
from mlkem.errors import (
    InvalidCiphertextLengthError, InvalidDecapsulationKeyError,
    InvalidEncapsulationKeyError, InvalidKeyLengthError, InvalidVariantError,
)
from mlkem.kem import decaps_internal, encaps_internal, keygen_internal
from mlkem.params import VARIANTS

NAMES = list(VARIANTS)


@pytest.mark.parametrize("name", NAMES)
def test_roundtrip(name):
    ek, dk = mlkem.keygen(name)
    K, c = mlkem.encaps(ek)  # variante déduite de la taille de ek
    assert len(K) == 32
    assert mlkem.decaps(dk, c) == K  # variante déduite de la taille de dk
    assert mlkem.decaps(dk, c, name) == K
    K2, c2 = mlkem.encaps(ek, name)
    assert c2 != c and K2 != K  # aléa frais à chaque encapsulation


@pytest.mark.parametrize("name", NAMES)
def test_implicit_rejection(name):
    p = VARIANTS[name]
    ek, dk = mlkem.keygen(name)
    K, c = mlkem.encaps(ek)
    z = dk[-32:]
    for pos in (0, len(c) // 2, len(c) - 1):
        bad = bytearray(c)
        bad[pos] ^= 0x01
        K_bad = mlkem.decaps(dk, bytes(bad))  # aucune exception
        assert K_bad != K
        assert K_bad == hashlib.shake_256(z + bytes(bad)).digest(32)  # J(z || c)


def test_internal_deterministic():
    d, z, m = b"\x0a" * 32, b"\x0b" * 32, b"\x0c" * 32
    ek, dk = keygen_internal(d, z, "ML-KEM-768")
    assert (ek, dk) == keygen_internal(d, z, "ML-KEM-768")
    K, c = encaps_internal(ek, m)
    assert (K, c) == encaps_internal(ek, m, "ML-KEM-768")
    assert decaps_internal(dk, c) == K


def test_dk_layout():
    p = VARIANTS["ML-KEM-512"]
    ek, dk = keygen_internal(b"\x01" * 32, b"\x02" * 32, p)
    k = p.k
    assert dk[384 * k: 768 * k + 32] == ek
    assert dk[768 * k + 32: 768 * k + 64] == hashlib.sha3_256(ek).digest()
    assert dk[-32:] == b"\x02" * 32


def test_unknown_variant_sizes():
    with pytest.raises(InvalidVariantError):
        mlkem.encaps(b"\x00" * 100)
    with pytest.raises(InvalidVariantError):
        mlkem.decaps(b"\x00" * 100, b"\x00" * 768)
    with pytest.raises(InvalidVariantError):
        mlkem.keygen("ML-KEM-999")


def test_wrong_lengths():
    ek, dk = mlkem.keygen("ML-KEM-512")
    K, c = mlkem.encaps(ek)
    with pytest.raises(InvalidKeyLengthError):
        mlkem.encaps(ek, "ML-KEM-768")  # variante fournie incohérente
    with pytest.raises(InvalidKeyLengthError):
        mlkem.decaps(dk, c, "ML-KEM-768")
    with pytest.raises(InvalidCiphertextLengthError):
        mlkem.decaps(dk, c[:-1])
    with pytest.raises(InvalidCiphertextLengthError):
        mlkem.decaps(dk, c + b"\x00")


def test_corrupted_keys():
    ek, dk = mlkem.keygen("ML-KEM-512")
    # coefficient de t = 4095 >= q : échec du contrôle de modulus
    bad_ek = b"\xff" + bytes([ek[1] | 0x0F]) + ek[2:]
    with pytest.raises(InvalidEncapsulationKeyError):
        mlkem.encaps(bad_ek)
    K, c = mlkem.encaps(ek)
    k = 2
    bad_dk = bytearray(dk)
    bad_dk[768 * k + 32] ^= 0x01  # corrompt H(ek) stocké
    with pytest.raises(InvalidDecapsulationKeyError):
        mlkem.decaps(bytes(bad_dk), c)
