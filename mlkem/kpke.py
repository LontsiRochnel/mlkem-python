"""K-PKE : schéma de chiffrement à clé publique sous-jacent à ML-KEM.

Rôle dans l'architecture (2/3 : paramètres, puis K-PKE, puis ML-KEM) :
K-PKE est un chiffrement de messages de 32 octets fondé sur le problème
Module-LWE. Il est utilisable seul (voir ``examples/kpke_demo.py``) mais
n'est sûr que contre les attaques à clair choisi : la transformation de
Fujisaki-Okamoto de ``kem.py`` en fait un mécanisme d'encapsulation sûr
contre les attaques à chiffré choisi.

Notations : ρ graine publique, σ graine du bruit, Â matrice dans le
domaine NTT, ŝ, t̂ vecteurs dans le domaine NTT, u et v composantes du
texte chiffré.
"""

from .arith import multiply_ntts, ntt, ntt_inv, poly_add, poly_sub
from .encoding import (
    byte_decode,
    byte_encode,
    compress_poly,
    decompress_poly,
)
from .errors import InvalidInputLengthError, InvalidKeyLengthError, InvalidCiphertextLengthError
from .params import Params, get_params
from .sampling import G, prf, sample_ntt, sample_poly_cbd, xof_input

Poly = list[int]


def _gen_matrix(rho: bytes, k: int) -> list[list[Poly]]:
    """Génère la matrice publique Â (k×k) à partir de ρ via SampleNTT.

    Args:
        rho: Graine publique, 32 octets.
        k: Dimension.

    Returns:
        Matrice A[i][j] de polynômes dans le domaine NTT.
    """
    # Â[i][j] = SampleNTT(ρ || j || i)
    return [[sample_ntt(xof_input(rho, j, i)) for j in range(k)] for i in range(k)]


def _mat_vec(A: list[list[Poly]], v: list[Poly], k: int, transpose: bool) -> list[Poly]:
    """Produit matrice-vecteur dans le domaine NTT (Â∘v ou Âᵀ∘v).

    Args:
        A: Matrice k×k dans le domaine NTT.
        v: Vecteur de k polynômes dans le domaine NTT.
        k: Dimension.
        transpose: Si vrai, utilise la transposée de A.

    Returns:
        Vecteur de k polynômes dans le domaine NTT.
    """
    out = []
    for i in range(k):
        acc = [0] * 256
        for j in range(k):
            a = A[j][i] if transpose else A[i][j]
            acc = poly_add(acc, multiply_ntts(a, v[j]))
        out.append(acc)
    return out


def _dot(a: list[Poly], b: list[Poly]) -> Poly:
    """Produit scalaire de deux vecteurs dans le domaine NTT.

    Args:
        a: Vecteur de polynômes (domaine NTT).
        b: Vecteur de polynômes (domaine NTT).

    Returns:
        Polynôme (domaine NTT) somme des produits composante par composante.
    """
    acc = [0] * 256
    for x, y in zip(a, b):
        acc = poly_add(acc, multiply_ntts(x, y))
    return acc


def _check_len(name: str, data: bytes, size: int) -> None:
    """Vérifie la longueur d'une entrée.

    Args:
        name: Nom de l'entrée (pour le message d'erreur).
        data: Valeur à contrôler.
        size: Longueur attendue en octets.

    Raises:
        InvalidInputLengthError: Si ``len(data) != size``.
    """
    if len(data) != size:
        raise InvalidInputLengthError(f"{name} : {size} octets attendus, {len(data)} reçus")


def kpke_keygen(d: bytes, variant) -> tuple[bytes, bytes]:
    """K-PKE.KeyGen : génère une paire de clés K-PKE de façon déterministe.

    TODO(verifier) : FIPS 203 (version finale) dérive (ρ, σ) de
    G(d || k), l'octet k étant le paramètre de la variante ; confirmer.

    Args:
        d: Graine de 32 octets (aléa à fournir par l'appelant).
        variant: ``Params`` ou nom de variante.

    Returns:
        Le couple (ek_PKE, dk_PKE) : ek_PKE = ByteEncode_12(t̂) || ρ
        (384k + 32 octets), dk_PKE = ByteEncode_12(ŝ) (384k octets).

    Raises:
        InvalidInputLengthError: Si ``d`` ne fait pas 32 octets.
        InvalidVariantError: Si la variante est inconnue.
    """
    p = get_params(variant)
    _check_len("d", d, 32)
    rho, sigma = G(d + bytes([p.k]))  # séparation de domaine par l'octet k
    A = _gen_matrix(rho, p.k)
    counter = 0  # compteur N de PRF : jamais réutilisé pour s et e
    s, e = [], []
    for _ in range(p.k):
        s.append(sample_poly_cbd(prf(p.eta1, sigma, counter), p.eta1))
        counter += 1
    for _ in range(p.k):
        e.append(sample_poly_cbd(prf(p.eta1, sigma, counter), p.eta1))
        counter += 1
    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]
    # t̂ = Â∘ŝ + ê
    t_hat = [poly_add(x, y) for x, y in zip(_mat_vec(A, s_hat, p.k, False), e_hat)]
    ek_pke = b"".join(byte_encode(x, 12) for x in t_hat) + rho
    dk_pke = b"".join(byte_encode(x, 12) for x in s_hat)
    return ek_pke, dk_pke


def kpke_encrypt(ek_pke: bytes, m: bytes, r: bytes, variant) -> bytes:
    """K-PKE.Encrypt : chiffre un message de 32 octets avec l'aléa r.

    Déterministe : l'aléa r (32 octets) est un paramètre explicite.

    Args:
        ek_pke: Clé de chiffrement, 384k + 32 octets.
        m: Message de 32 octets.
        r: Aléa de chiffrement de 32 octets.
        variant: ``Params`` ou nom de variante.

    Returns:
        Texte chiffré c = c1 || c2 (32(du·k + dv) octets).

    Raises:
        InvalidKeyLengthError: Si ek_pke a une mauvaise longueur.
        InvalidInputLengthError: Si m ou r ne font pas 32 octets.
    """
    p = get_params(variant)
    if len(ek_pke) != p.ek_size:
        raise InvalidKeyLengthError(f"ek_PKE : {p.ek_size} octets attendus")
    _check_len("m", m, 32)
    _check_len("r", r, 32)
    t_hat = [byte_decode(ek_pke[384 * i: 384 * (i + 1)], 12) for i in range(p.k)]
    rho = ek_pke[384 * p.k:]
    A = _gen_matrix(rho, p.k)
    counter = 0
    y, e1 = [], []
    for _ in range(p.k):
        y.append(sample_poly_cbd(prf(p.eta1, r, counter), p.eta1))
        counter += 1
    for _ in range(p.k):
        e1.append(sample_poly_cbd(prf(p.eta2, r, counter), p.eta2))
        counter += 1
    e2 = sample_poly_cbd(prf(p.eta2, r, counter), p.eta2)
    y_hat = [ntt(x) for x in y]
    # u = NTT⁻¹(Âᵀ∘ŷ) + e1
    u = [
        poly_add(ntt_inv(x), e)
        for x, e in zip(_mat_vec(A, y_hat, p.k, True), e1)
    ]
    # μ = Decompress_1(ByteDecode_1(m)) : chaque bit du message -> 0 ou ⌈q/2⌋
    mu = decompress_poly(byte_decode(m, 1), 1)
    # v = NTT⁻¹(t̂ᵀ∘ŷ) + e2 + μ
    v = poly_add(poly_add(ntt_inv(_dot(t_hat, y_hat)), e2), mu)
    c1 = b"".join(byte_encode(compress_poly(x, p.du), p.du) for x in u)
    c2 = byte_encode(compress_poly(v, p.dv), p.dv)
    return c1 + c2


def kpke_decrypt(dk_pke: bytes, c: bytes, variant) -> bytes:
    """K-PKE.Decrypt : déchiffre un texte chiffré K-PKE.

    Args:
        dk_pke: Clé de déchiffrement, 384k octets.
        c: Texte chiffré, 32(du·k + dv) octets.
        variant: ``Params`` ou nom de variante.

    Returns:
        Le message de 32 octets.

    Raises:
        InvalidKeyLengthError: Si dk_pke a une mauvaise longueur.
        InvalidCiphertextLengthError: Si c a une mauvaise longueur.
    """
    p = get_params(variant)
    if len(dk_pke) != p.dk_pke_size:
        raise InvalidKeyLengthError(f"dk_PKE : {p.dk_pke_size} octets attendus")
    if len(c) != p.c_size:
        raise InvalidCiphertextLengthError(f"c : {p.c_size} octets attendus")
    n1 = 32 * p.du  # taille en octets d'un polynôme u compressé
    u = [
        decompress_poly(byte_decode(c[n1 * i: n1 * (i + 1)], p.du), p.du)
        for i in range(p.k)
    ]
    v = decompress_poly(byte_decode(c[n1 * p.k:], p.dv), p.dv)
    s_hat = [byte_decode(dk_pke[384 * i: 384 * (i + 1)], 12) for i in range(p.k)]
    # w = v' − NTT⁻¹(ŝᵀ∘NTT(u'))
    w = poly_sub(v, ntt_inv(_dot(s_hat, [ntt(x) for x in u])))
    # m = ByteEncode_1(Compress_1(w)) : bit 1 si w est proche de q/2
    return byte_encode(compress_poly(w, 1), 1)
