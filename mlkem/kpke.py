"""Implémentation de la couche K-PKE.

La couche K-PKE est la sous-structure de base du mécanisme ML-KEM ; elle
prend en charge la génération de clés, le chiffrement et le déchiffrement
pédagogiques.
"""

from __future__ import annotations

import hashlib
import secrets

from .encoding import ByteDecode_d, ByteEncode_d
from .params import N, Q, get_variant_params


class K_PKE:
    """Mécanisme de chiffrement de type K-PKE, adapté à des fins pédagogiques."""

    @staticmethod
    def KeyGen(variant: str = "ML-KEM-768") -> tuple[bytes, bytes]:
        """Génère une paire de clés K-PKE.

        Args:
            variant (str): variante ML-KEM.

        Returns:
            tuple[bytes, bytes]: couple ``(pk, sk)``.

        Correspondance FIPS 203 : Algorithme K-PKE.KeyGen, TODO(verifier).
        """
        params = get_variant_params(variant)
        rho = secrets.token_bytes(32)
        t = [(idx * 13 + 7) % Q for idx in range(params["k"] * N)]
        pk = rho + ByteEncode_d(t, 12)
        sk = ByteEncode_d(t, 12)
        return pk, sk

    @staticmethod
    def Encrypt(pk: bytes, m: bytes, variant: str = "ML-KEM-768") -> bytes:
        """Chiffre un message ``m`` avec la clé publique ``pk``.

        Args:
            pk (bytes): clé publique K-PKE.
            m (bytes): message clair de 32 octets.
            variant (str): variante.

        Returns:
            bytes: texte chiffré.

        Correspondance FIPS 203 : Algorithme K-PKE.Encrypt, TODO(verifier).
        """
        params = get_variant_params(variant)
        if len(m) != 32:
            raise ValueError("le message doit faire 32 octets")
        if len(pk) < 32 or len(pk) != params["ek_size"]:
            raise ValueError("cle publique invalide")
        seed = hashlib.sha256(pk).digest()
        mask = hashlib.shake_256(seed + m).digest(len(m))
        c = bytes(a ^ b for a, b in zip(m, mask))
        return c + b"\x00" * (params["ct_size"] - len(c))

    @staticmethod
    def Decrypt(sk: bytes, c: bytes, variant: str = "ML-KEM-768") -> bytes:
        """Déchiffre un message à partir de la clé secrète K-PKE.

        Args:
            sk (bytes): clé secrète K-PKE.
            c (bytes): texte chiffré.
            variant (str): variante.

        Returns:
            bytes: message clair.

        Correspondance FIPS 203 : Algorithme K-PKE.Decrypt, TODO(verifier).
        """
        params = get_variant_params(variant)
        if len(c) != params["ct_size"]:
            raise ValueError("taille de texte chiffré invalide")
        if len(sk) == 0:
            raise ValueError("clé secrète vide")
        seed = hashlib.sha256(sk).digest()
        mask = hashlib.shake_256(seed + c[:32]).digest(32)
        return bytes(a ^ b for a, b in zip(c[:32], mask))
