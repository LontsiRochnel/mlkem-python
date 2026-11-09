import pytest

from mlkem import CT_SIZE, ML_KEM_1024, ML_KEM_512, ML_KEM_768, decaps, encaps, keygen
from mlkem.errors import InvalidCiphertextError, InvalidKeyError, InvalidSizeError


@pytest.mark.parametrize("variant", [ML_KEM_512, ML_KEM_768, ML_KEM_1024])
def test_kem_roundtrip(variant):
    ek, dk = keygen(variant)
    K_a, c = encaps(ek, variant)
    K_b = decaps(dk, c, variant)
    assert len(K_a) == 32
    assert len(K_b) == 32
    assert K_a == K_b


def test_implicit_rejection():
    ek, dk = keygen(ML_KEM_768)
    K_a, c = encaps(ek, ML_KEM_768)
    tampered = bytearray(c)
    tampered[0] ^= 1
    K_b = decaps(dk, bytes(tampered), ML_KEM_768)
    assert K_b != K_a
    assert len(K_b) == 32


def test_invalid_inputs():
    ek, dk = keygen(ML_KEM_768)
    with pytest.raises(InvalidKeyError):
        encaps(b"\x00" * 10)
    with pytest.raises(InvalidCiphertextError):
        decaps(dk, b"\x00" * 10, ML_KEM_768)
    bad_ek = bytearray(ek)
    bad_ek[-1] ^= 0xFF
    with pytest.raises(InvalidKeyError):
        encaps(bytes(bad_ek), ML_KEM_768)


def test_invalid_variant_size_raises():
    with pytest.raises(InvalidKeyError):
        encaps(b"\x00" * 123)
    with pytest.raises(InvalidSizeError):
        decaps(b"\x00" * 123, b"\x00" * 32)
