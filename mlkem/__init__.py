"""ML-KEM (FIPS 203) et K-PKE : implémentation pédagogique en Python pur.

API publique : ``keygen``, ``encaps``, ``decaps``, les constantes de
variantes et de tailles, et les exceptions. K-PKE seul se trouve dans
``mlkem.kpke``. Projet pédagogique, non audité, non destiné à la
production (voir README).
"""

from .errors import (
    InvalidCiphertextLengthError,
    InvalidDecapsulationKeyError,
    InvalidEncapsulationKeyError,
    InvalidInputLengthError,
    InvalidKeyLengthError,
    InvalidVariantError,
    MLKEMError,
)
from .kem import decaps, encaps, keygen
from .params import ML_KEM_512, ML_KEM_768, ML_KEM_1024, VARIANTS, Params

# Tailles en octets par variante : (ek, dk, c, K)
SIZES = {
    name: (p.ek_size, p.dk_size, p.c_size, p.K_size) for name, p in VARIANTS.items()
}

__all__ = [
    "keygen", "encaps", "decaps",
    "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024", "VARIANTS", "SIZES", "Params",
    "MLKEMError", "InvalidVariantError", "InvalidInputLengthError",
    "InvalidKeyLengthError", "InvalidCiphertextLengthError",
    "InvalidEncapsulationKeyError", "InvalidDecapsulationKeyError",
]
