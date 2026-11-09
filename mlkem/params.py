"""Paramètres du standard ML-KEM.

Ce module contient les paramètres des variantes ML-KEM-512, ML-KEM-768 et
ML-KEM-1024. Il fournit aussi la table des tailles publiques du standard.
"""

from __future__ import annotations

Q = 3329
N = 256
ZETA = 17

ML_KEM_512 = "ML-KEM-512"
ML_KEM_768 = "ML-KEM-768"
ML_KEM_1024 = "ML-KEM-1024"

VARIANTS = {
    ML_KEM_512: {
        "k": 2,
        "eta1": 3,
        "eta2": 2,
        "du": 10,
        "dv": 4,
        "ek_size": 800,
        "dk_size": 1632,
        "ct_size": 768,
    },
    ML_KEM_768: {
        "k": 3,
        "eta1": 2,
        "eta2": 2,
        "du": 10,
        "dv": 4,
        "ek_size": 1184,
        "dk_size": 2400,
        "ct_size": 1088,
    },
    ML_KEM_1024: {
        "k": 4,
        "eta1": 2,
        "eta2": 2,
        "du": 11,
        "dv": 5,
        "ek_size": 1568,
        "dk_size": 3168,
        "ct_size": 1568,
    },
}

SS_SIZE = 32

EK_SIZE = {ML_KEM_512: 800, ML_KEM_768: 1184, ML_KEM_1024: 1568}
DK_SIZE = {ML_KEM_512: 1632, ML_KEM_768: 2400, ML_KEM_1024: 3168}
CT_SIZE = {ML_KEM_512: 768, ML_KEM_768: 1088, ML_KEM_1024: 1568}


def get_variant_params(variant: str) -> dict:
    """Retourne les paramètres d'une variante ML-KEM donnée.

    Args:
        variant (str): nom de la variante, par exemple ``ML-KEM-768``.

    Returns:
        dict: dictionnaire contenant les paramètres ``k``, ``eta1``, ``eta2``,
        ``du``, ``dv`` et tailles de clé.

    Raises:
        ValueError: si la variante est inconnue.
    """
    try:
        return VARIANTS[variant]
    except KeyError as exc:
        raise ValueError(f"variante inconnue: {variant}") from exc


def detect_variant_by_ek(ek: bytes) -> str:
    """Déduit la variante à partir d'une clé publique."""
    size = len(ek)
    for name, params in VARIANTS.items():
        if params["ek_size"] == size:
            return name
    raise ValueError("taille de clé publique inconnue")


def detect_variant_by_dk(dk: bytes) -> str:
    """Déduit la variante à partir d'une clé privée."""
    size = len(dk)
    for name, params in VARIANTS.items():
        if params["dk_size"] == size:
            return name
    raise ValueError("taille de clé privée inconnue")
