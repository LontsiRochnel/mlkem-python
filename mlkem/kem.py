"""ML-KEM : mécanisme d'encapsulation de clés (FIPS 203).

Rôle dans l'architecture (3/3 : paramètres, puis K-PKE, puis ML-KEM) :
enveloppe K-PKE dans la transformation de Fujisaki-Okamoto (FO) :

* Encaps : m aléatoire, (K, r) = G(m || H(ek)), c = K-PKE.Encrypt(ek, m, r).
* Decaps : déchiffre m', recalcule (K', r') et rechiffre c'. Si c' = c
  (comparaison en temps constant) renvoie K', sinon renvoie J(z || c)
  (*rejet implicite* : jamais d'erreur visible pour un texte modifié).

Les variantes ``*_internal`` sont déterministes (aléa passé en argument),
pour les tests. Les fonctions publiques ``keygen``, ``encaps`` et
``decaps`` ajoutent la génération d'aléa (``secrets``) et les contrôles
d'entrée de FIPS 203.

Format : dk = dk_PKE || ek || H(ek) || z.
"""

import hmac
import secrets

from .encoding import byte_decode, byte_encode
from .errors import (
    InvalidCiphertextLengthError,
    InvalidDecapsulationKeyError,
    InvalidEncapsulationKeyError,
    InvalidInputLengthError,
    InvalidKeyLengthError,
)
from .kpke import kpke_decrypt, kpke_encrypt, kpke_keygen
from .params import get_params, params_from_dk_size, params_from_ek_size
from .sampling import G, H, J


def keygen_internal(d: bytes, z: bytes, variant) -> tuple[bytes, bytes]:
    """ML-KEM.KeyGen_internal : génération de clés déterministe.

    Args:
        d: Graine de 32 octets pour K-PKE.KeyGen.
        z: Valeur de 32 octets pour le rejet implicite.
        variant: ``Params`` ou nom de variante.

    Returns:
        Le couple (ek, dk), de tailles ek_size et dk_size.

    Raises:
        InvalidInputLengthError: Si d ou z ne font pas 32 octets.
    """
    p = get_params(variant)
    if len(d) != 32 or len(z) != 32:
        raise InvalidInputLengthError("d et z doivent faire 32 octets")
    ek_pke, dk_pke = kpke_keygen(d, p)
    ek = ek_pke  # la clé d'encapsulation ML-KEM est celle de K-PKE
    # Ordre de concaténation de dk : dk_PKE || ek || H(ek) || z
    dk = dk_pke + ek + H(ek) + z
    return ek, dk


def encaps_internal(ek: bytes, m: bytes, variant=None) -> tuple[bytes, bytes]:
    """ML-KEM.Encaps_internal : encapsulation déterministe.

    Args:
        ek: Clé d'encapsulation (384k + 32 octets).
        m: Message aléatoire de 32 octets.
        variant: ``Params``, nom, ou None (déduit de la taille de ek).

    Returns:
        Le couple (K, c) : clé partagée (32 octets) et texte chiffré.

    Raises:
        InvalidInputLengthError: Si m ne fait pas 32 octets.
    """
    p = get_params(variant) if variant is not None else params_from_ek_size(len(ek))
    if len(m) != 32:
        raise InvalidInputLengthError("m doit faire 32 octets")
    K, r = G(m + H(ek))  # (K, r) = G(m || H(ek))
    c = kpke_encrypt(ek, m, r, p)
    return K, c


def decaps_internal(dk: bytes, c: bytes, variant=None) -> bytes:
    """ML-KEM.Decaps_internal : décapsulation avec rejet implicite.

    Aucun contrôle de longueur ici (voir ``decaps``) hormis ceux de K-PKE.

    Args:
        dk: Clé de décapsulation (768k + 96 octets).
        c: Texte chiffré.
        variant: ``Params``, nom, ou None (déduit de la taille de dk).

    Returns:
        La clé partagée K (32 octets). Si c n'est pas le chiffrement
        attendu, renvoie J(z || c) sans lever d'exception.
    """
    p = get_params(variant) if variant is not None else params_from_dk_size(len(dk))
    k = p.k
    # Découpage de dk = dk_PKE || ek || H(ek) || z
    dk_pke = dk[0: 384 * k]
    ek = dk[384 * k: 768 * k + 32]
    h = dk[768 * k + 32: 768 * k + 64]
    z = dk[768 * k + 64: 768 * k + 96]
    m_prime = kpke_decrypt(dk_pke, c, p)
    K_prime, r_prime = G(m_prime + h)
    K_bar = J(z + c)  # valeur de rejet implicite
    c_prime = kpke_encrypt(ek, m_prime, r_prime, p)  # rechiffrement (FO)
    # Comparaison en temps constant ; le choix final est fait sans erreur
    if hmac.compare_digest(c, c_prime):
        return K_prime
    return K_bar


def keygen(variant) -> tuple[bytes, bytes]:
    """ML-KEM.KeyGen : génère une paire (ek, dk) avec de l'aléa frais.

    Args:
        variant: ``Params`` ou nom (``"ML-KEM-768"``...).

    Returns:
        Le couple (ek, dk) en octets.

    Raises:
        InvalidVariantError: Si la variante est inconnue.
    """
    p = get_params(variant)
    return keygen_internal(secrets.token_bytes(32), secrets.token_bytes(32), p)


def check_encapsulation_key(ek: bytes, p) -> None:
    """Contrôle d'entrée de FIPS 203 sur la clé d'encapsulation.

    Vérifie la longueur, puis l'aller-retour
    ByteEncode_12(ByteDecode_12(t)) = t (tous les coefficients < q).

    Args:
        ek: Clé d'encapsulation.
        p: Jeu de paramètres (``Params``).

    Raises:
        InvalidKeyLengthError: Si len(ek) != 384k + 32.
        InvalidEncapsulationKeyError: Si le contrôle de modulus échoue.
    """
    if len(ek) != p.ek_size:
        raise InvalidKeyLengthError(f"ek : {p.ek_size} octets attendus, {len(ek)} reçus")
    for i in range(p.k):
        chunk = ek[384 * i: 384 * (i + 1)]
        if byte_encode(byte_decode(chunk, 12), 12) != chunk:
            raise InvalidEncapsulationKeyError("coefficient de t non réduit modulo q")


def check_decapsulation_key(dk: bytes, p) -> None:
    """Contrôle d'entrée de FIPS 203 sur la clé de décapsulation.

    Vérifie la longueur, puis que le H(ek) stocké dans dk est bien
    H de l'ek stocké dans dk.

    Args:
        dk: Clé de décapsulation.
        p: Jeu de paramètres (``Params``).

    Raises:
        InvalidKeyLengthError: Si len(dk) != 768k + 96.
        InvalidDecapsulationKeyError: Si H(ek) ne correspond pas.
    """
    if len(dk) != p.dk_size:
        raise InvalidKeyLengthError(f"dk : {p.dk_size} octets attendus, {len(dk)} reçus")
    ek = dk[384 * p.k: 768 * p.k + 32]
    h = dk[768 * p.k + 32: 768 * p.k + 64]
    if not hmac.compare_digest(H(ek), h):
        raise InvalidDecapsulationKeyError("H(ek) stocké différent de H(ek)")


def encaps(ek: bytes, variant=None) -> tuple[bytes, bytes]:
    """ML-KEM.Encaps : encapsule une clé partagée sous ek.

    Args:
        ek: Clé d'encapsulation (octets).
        variant: ``Params``, nom, ou None (déduit de la taille de ek).

    Returns:
        Le couple (K, c) : clé partagée de 32 octets et texte chiffré.

    Raises:
        InvalidVariantError: Si la taille de ek ne correspond à aucune variante.
        InvalidKeyLengthError: Si la taille de ek ne correspond pas à la variante.
        InvalidEncapsulationKeyError: Si ek échoue au contrôle de modulus.
    """
    ek = bytes(ek)
    p = get_params(variant) if variant is not None else params_from_ek_size(len(ek))
    check_encapsulation_key(ek, p)
    return encaps_internal(ek, secrets.token_bytes(32), p)


def decaps(dk: bytes, c: bytes, variant=None) -> bytes:
    """ML-KEM.Decaps : retrouve la clé partagée à partir de c.

    Un texte chiffré modifié ne provoque *pas* d'erreur : la sortie est
    alors une clé pseudo-aléatoire J(z || c) (rejet implicite).

    Args:
        dk: Clé de décapsulation (octets).
        c: Texte chiffré (octets).
        variant: ``Params``, nom, ou None (déduit de la taille de dk).

    Returns:
        La clé partagée K (32 octets).

    Raises:
        InvalidVariantError: Si la taille de dk ne correspond à aucune variante.
        InvalidKeyLengthError: Si la taille de dk ne correspond pas à la variante.
        InvalidCiphertextLengthError: Si la taille de c est incorrecte.
        InvalidDecapsulationKeyError: Si H(ek) stocké dans dk est incorrect.
    """
    dk, c = bytes(dk), bytes(c)
    p = get_params(variant) if variant is not None else params_from_dk_size(len(dk))
    if len(dk) != p.dk_size:  # longueur de dk d'abord, puis de c, puis H(ek)
        raise InvalidKeyLengthError(f"dk : {p.dk_size} octets attendus, {len(dk)} reçus")
    if len(c) != p.c_size:
        raise InvalidCiphertextLengthError(f"c : {p.c_size} octets attendus, {len(c)} reçus")
    check_decapsulation_key(dk, p)
    return decaps_internal(dk, c, p)
