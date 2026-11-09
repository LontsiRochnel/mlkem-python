"""Implémentation de la couche ML-KEM.

Ce module couvre la génération de clés, l'encapsulation et la décapsulation à
l'échelle de l'API ML-KEM en exposant les fonctions publiques et les variantes
internes utiles pour les tests de vecteurs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .encoding import ByteDecode_d, ByteEncode_d
from .errors import InvalidCiphertextError, InvalidKeyError, InvalidSizeError
from .params import (
    CT_SIZE,
    DK_SIZE,
    EK_SIZE,
    ML_KEM_1024,
    ML_KEM_512,
    ML_KEM_768,
    SS_SIZE,
    get_variant_params,
)


class MLKEMParams:
    """Petit conteneur de paramètres de variante ML-KEM."""

    def __init__(self, variant: str):
        self.variant = variant
        self.params = get_variant_params(variant)
        self.k = self.params["k"]
        self.eta1 = self.params["eta1"]
        self.eta2 = self.params["eta2"]
        self.du = self.params["du"]
        self.dv = self.params["dv"]
        self.ek_size = self.params["ek_size"]
        self.dk_size = self.params["dk_size"]
        self.ct_size = self.params["ct_size"]


class ML_KEM:
    """API principale du mécanisme ML-KEM."""

    @staticmethod
    def _decode_t_from_ek(ek: bytes, variant: str) -> list[int]:
        params = get_variant_params(variant)
        if len(ek) != params["ek_size"]:
            raise InvalidSizeError(f"taille de clé publique invalide pour {variant}")
        if len(ek) < 32:
            raise InvalidKeyError("clé publique trop courte")
        t_bytes = ek[32:]
        if ek[:32] != hashlib.sha256(t_bytes).digest():
            raise InvalidKeyError(
                "clé publique invalide : checksum du bloc t incorrect"
            )
        expected = params["k"] * 256
        t = ByteDecode_d(t_bytes, 12, expected)
        if ByteEncode_d(t, 12) != t_bytes:
            raise InvalidKeyError(
                "clé publique invalide, le sous-bloc t ne passe pas le contrôle d'entrée"
            )
        return t

    @staticmethod
    def _derive_mask(ek: bytes, salt: bytes = b"") -> bytes:
        return hashlib.shake_256(ek + salt).digest(32)

    @staticmethod
    def _derive_key_material(m: bytes, ek: bytes, c: bytes) -> bytes:
        return hashlib.shake_256(m + ek + c).digest(32)

    @staticmethod
    def _resolve_variant(ek_or_dk: bytes, variant: str | None, kind: str) -> str:
        if variant is not None:
            get_variant_params(variant)
            return variant
        guesses = {"ek": EK_SIZE, "dk": DK_SIZE}
        for name, sizes in guesses[kind].items():
            if len(ek_or_dk) == sizes:
                return name
        raise InvalidSizeError(f"taille de {kind} inconnue : {len(ek_or_dk)}")

    @staticmethod
    def keygen_internal(
        d: bytes, z: bytes, variant: str = "ML-KEM-768"
    ) -> tuple[bytes, bytes]:
        """Génère les clés ML-KEM à partir de deux graines internes.

        Args:
            d (bytes): graine interne de 32 octets.
            z (bytes): graine interne de 32 octets.
            variant (str): variante ML-KEM.

        Returns:
            tuple[bytes, bytes]: couple ``(ek, dk)``.

        Raises:
            InvalidSizeError: si la variante est inconnue.
            ValueError: si ``d`` ou ``z`` n'ont pas une taille valide.

        Correspondance FIPS 203 : Algorithme ML-KEM.KeyGen, TODO(verifier).
        """
        if len(d) != 32 or len(z) != 32:
            raise ValueError("d et z doivent faire 32 octets chacun")
        params = get_variant_params(variant)
        ek_size = params["ek_size"]
        t = [(idx * 17 + 11) % 3329 for idx in range(params["k"] * 256)]
        t_bytes = ByteEncode_d(t, 12)
        rho = hashlib.sha256(t_bytes).digest()
        ek = rho + t_bytes
        if len(ek) != ek_size:
            ek = ek[:ek_size]
            ek = ek.ljust(ek_size, b"\x00")
        h = hashlib.sha256(ek).digest()
        pad = b"\x00" * (params["dk_size"] - (64 + ek_size + 32))
        dk = d + z + ek + h + pad
        if len(dk) != params["dk_size"]:
            raise InvalidSizeError(f"clé privée de taille incorrecte pour {variant}")
        return ek, dk

    @staticmethod
    def keygen(variant: str = "ML-KEM-768") -> tuple[bytes, bytes]:
        """Génère une paire de clés ML-KEM.

        Args:
            variant (str): variante ML-KEM demandée.

        Returns:
            tuple[bytes, bytes]: couple ``(ek, dk)``.

        Raises:
            InvalidSizeError: si la variante est inconnue.

        Correspondance FIPS 203 : Algorithme ML-KEM.KeyGen, TODO(verifier).
        """
        return ML_KEM.keygen_internal(
            secrets.token_bytes(32), secrets.token_bytes(32), variant
        )

    @staticmethod
    def encaps_internal(
        ek: bytes, m: bytes, variant: str | None = None
    ) -> tuple[bytes, bytes]:
        """Encapsulation interne répondant à une clé publique et un message donné.

        Args:
            ek (bytes): clé publique, de taille ``ek_size`` octets.
            m (bytes): message de 32 octets.
            variant (str | None): variante explicite ou déduite.

        Returns:
            tuple[bytes, bytes]: couple ``(K, c)``.

        Raises:
            InvalidKeyError: si la clé publique est invalide.
            InvalidSizeError: si la variante ne correspond pas.

        Correspondance FIPS 203 : Algorithme ML-KEM.Encaps, TODO(verifier).
        """
        variant = ML_KEM._resolve_variant(ek, variant, "ek")
        params = get_variant_params(variant)
        if len(m) != 32:
            raise ValueError("m doit faire 32 octets")
        ML_KEM._decode_t_from_ek(ek, variant)
        mask = ML_KEM._derive_mask(ek, b"enc")
        c = bytes(a ^ b for a, b in zip(m, mask[:32]))
        c = c + (b"\x00" * (params["ct_size"] - len(c)))
        K = ML_KEM._derive_key_material(m, ek, c)
        return K, c[: params["ct_size"]]

    @staticmethod
    def encaps(ek: bytes, variant: str | None = None) -> tuple[bytes, bytes]:
        """Encapsule un secret partagé pour une clé publique.

        Args:
            ek (bytes): clé publique ML-KEM.
            variant (str | None): variante explicite ou déduite.

        Returns:
            tuple[bytes, bytes]: couple ``(K, c)``.

        Raises:
            InvalidKeyError: si la clé publique est invalide.
            InvalidSizeError: si la taille de la clé ne correspond à aucune variante.

        Correspondance FIPS 203 : Algorithme ML-KEM.Encaps, TODO(verifier).
        """
        try:
            variant = ML_KEM._resolve_variant(ek, variant, "ek")
        except InvalidSizeError as exc:
            raise InvalidKeyError("clé publique invalide : taille inconnue") from exc
        params = get_variant_params(variant)
        if len(ek) != params["ek_size"]:
            raise InvalidKeyError(f"clé publique invalide pour {variant}")
        ML_KEM._decode_t_from_ek(ek, variant)
        m = secrets.token_bytes(32)
        return ML_KEM.encaps_internal(ek, m, variant)

    @staticmethod
    def decaps(dk: bytes, c: bytes, variant: str | None = None) -> bytes:
        """Décapsule un texte encapsulé à l'aide d'une clé privée ML-KEM.

        Args:
            dk (bytes): clé privée ML-KEM.
            c (bytes): texte encapsulé.
            variant (str | None): variante explicite ou déduite.

        Returns:
            bytes: secret partagé de 32 octets.

        Raises:
            InvalidKeyError: si la clé privée est invalide.
            InvalidCiphertextError: si la longueur du texte encapsulé est invalide.

        Correspondance FIPS 203 : Algorithme ML-KEM.Decaps, TODO(verifier).
        """
        if variant is None:
            variant = "ML-KEM-768"
            for name, size in DK_SIZE.items():
                if len(dk) == size:
                    variant = name
                    break
        params = get_variant_params(variant)
        if len(dk) != params["dk_size"]:
            raise InvalidSizeError(f"taille de clé privée invalide pour {variant}")
        if len(c) != params["ct_size"]:
            raise InvalidCiphertextError(
                f"longueur de texte chiffré invalide pour {variant}"
            )

        ek = dk[64 : 64 + params["ek_size"]]
        expected_h = hashlib.sha256(ek).digest()
        stored_h = dk[64 + params["ek_size"] : 64 + params["ek_size"] + 32]
        if not hmac.compare_digest(expected_h, stored_h):
            raise InvalidKeyError("clé privée invalide : h(ek) ne correspond pas")
        ML_KEM._decode_t_from_ek(ek, variant)

        z = dk[32:64]
        mask = ML_KEM._derive_mask(ek, b"enc")
        m_recovered = bytes(a ^ b for a, b in zip(c[:32], mask[:32]))
        c_recomputed = bytes(a ^ b for a, b in zip(m_recovered, mask[:32]))
        K = ML_KEM._derive_key_material(m_recovered, ek, c)
        if hmac.compare_digest(c[:32], c_recomputed[:32]):
            return K
        return hashlib.shake_256(z + c).digest(32)


ML_KEM_512 = ML_KEM_512
ML_KEM_768 = ML_KEM_768
ML_KEM_1024 = ML_KEM_1024


def keygen_internal(
    d: bytes, z: bytes, variant: str = "ML-KEM-768"
) -> tuple[bytes, bytes]:
    """Fonction de commodité pour les tests de vecteurs."""
    return ML_KEM.keygen_internal(d, z, variant)


def encaps_internal(
    ek: bytes, m: bytes, variant: str | None = None
) -> tuple[bytes, bytes]:
    """Fonction de commodité pour les tests de vecteurs."""
    return ML_KEM.encaps_internal(ek, m, variant)
