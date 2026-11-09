"""Module public de l'API ML-KEM.

Ce package expose une interface pédagogique et compacte pour générer des clés,
encapsuler un secret partagé et le décapsuler selon le mécanisme ML-KEM.
"""

from .errors import InvalidCiphertextError, InvalidKeyError, InvalidSizeError
from .kem import ML_KEM_1024, ML_KEM_512, ML_KEM_768, ML_KEM, MLKEMParams
from .params import (
    CT_SIZE,
    DK_SIZE,
    EK_SIZE,
    ML_KEM_1024 as PARAM_1024,
    ML_KEM_512 as PARAM_512,
    ML_KEM_768 as PARAM_768,
    SS_SIZE,
)

__all__ = [
    "ML_KEM_512",
    "ML_KEM_768",
    "ML_KEM_1024",
    "EK_SIZE",
    "DK_SIZE",
    "CT_SIZE",
    "SS_SIZE",
    "keygen",
    "encaps",
    "decaps",
    "MLKEMParams",
    "ML_KEM",
    "InvalidSizeError",
    "InvalidKeyError",
    "InvalidCiphertextError",
]


def keygen(variant: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """Génère une paire de clés d'encapsulation/décapsulation.

    Args:
        variant (str): variante ML-KEM demandée. Valeurs supportées :
            ``ML-KEM-512``, ``ML-KEM-768`` et ``ML-KEM-1024``.

    Returns:
        tuple[bytes, bytes]: couple ``(ek, dk)`` où ``ek`` est la clé
        d'encapsulation et ``dk`` la clé de décapsulation.

    Raises:
        InvalidSizeError: si la variante n'est pas reconnue.

    Correspondance FIPS 203 : Algorithme ML-KEM.KeyGen, TODO(verifier) ;
    l'API publique s'appuie sur la génération de clés décrite par la couche
    ML-KEM.
    """
    return ML_KEM.keygen(variant)


def encaps(ek: bytes, variant: str | None = None) -> tuple[bytes, bytes]:
    """Encapsule un secret partagé pour une clé publique donnée.

    Args:
        ek (bytes): clé d'encapsulation, sur ``ek_size`` octets.
        variant (str | None): variante explicite. Si ``None``, déduite à partir
            de la longueur de ``ek``.

    Returns:
        tuple[bytes, bytes]: couple ``(K, c)`` où ``K`` est le secret partagé
        de 32 octets et ``c`` le texte encapsulé.

    Raises:
        InvalidKeyError: si la clé publique ne passe pas le contrôle d'entrée.
        InvalidSizeError: si la variante est inconnue ou si la taille de la clé
            ne correspond à aucune variante.

    Correspondance FIPS 203 : Algorithme ML-KEM.Encaps, TODO(verifier).
    """
    return ML_KEM.encaps(ek, variant)


def decaps(dk: bytes, c: bytes, variant: str | None = None) -> bytes:
    """Décapsule un secret partagé à partir d'une clé privée et d'un texte.

    Args:
        dk (bytes): clé de décapsulation.
        c (bytes): texte encapsulé.
        variant (str | None): variante explicite. Si ``None``, déduite à partir
            de la longueur de ``dk``.

    Returns:
        bytes: secret partagé de 32 octets.

    Raises:
        InvalidKeyError: si la clé privée ne passe pas le contrôle d'entrée.
        InvalidCiphertextError: si la longueur du texte encapsulé est invalide.
        InvalidSizeError: si la variante est inconnue.

    Correspondance FIPS 203 : Algorithme ML-KEM.Decaps, TODO(verifier).
    """
    return ML_KEM.decaps(dk, c, variant)
