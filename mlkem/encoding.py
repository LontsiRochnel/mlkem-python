"""Encodage binaire et compression des polynômes.

Rôle dans l'architecture : passerelle entre les polynômes (listes de
256 entiers) et les octets des clés et des textes chiffrés. Contient
BitsToBytes, BytesToBits, ByteEncode_d, ByteDecode_d, Compress_d et
Decompress_d. Convention de FIPS 203 : les bits sont lus du poids faible
au poids fort à l'intérieur de chaque octet (petit-boutiste).
"""

from .params import N, Q


def bits_to_bytes(bits: list[int]) -> bytes:
    """Regroupe des bits en octets (BitsToBytes).

    Args:
        bits: Liste de bits (0 ou 1) dont la longueur est multiple de 8.

    Returns:
        Les octets, bit 0 = poids faible du premier octet.

    Raises:
        ValueError: Si la longueur n'est pas un multiple de 8.
    """
    if len(bits) % 8:
        raise ValueError("la longueur en bits doit être un multiple de 8")
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        out[i // 8] |= b << (i % 8)  # i % 8 : position dans l'octet
    return bytes(out)


def bytes_to_bits(data: bytes) -> list[int]:
    """Éclate des octets en bits (BytesToBits).

    Args:
        data: Octets à éclater.

    Returns:
        Liste de 8·len(data) bits, poids faible de chaque octet en premier.
    """
    return [(byte >> j) & 1 for byte in data for j in range(8)]


def byte_encode(F: list[int], d: int) -> bytes:
    """Encode 256 entiers de d bits en 32·d octets (ByteEncode_d).

    Args:
        F: 256 entiers. Dans [0, 2^d) si d < 12, dans [0, q) si d = 12.
        d: Nombre de bits par coefficient, 1 <= d <= 12.

    Returns:
        Une chaîne de 32·d octets.

    Raises:
        ValueError: Si d est hors bornes, si len(F) != 256 ou si un
            coefficient est hors de son intervalle.
    """
    if not 1 <= d <= 12:
        raise ValueError("d doit être dans [1, 12]")
    if len(F) != N:
        raise ValueError("un polynôme a 256 coefficients")
    m = Q if d == 12 else 1 << d  # modulus m de FIPS 203
    bits: list[int] = []
    for a in F:
        if not 0 <= a < m:
            raise ValueError(f"coefficient {a} hors de [0, {m})")
        bits.extend((a >> j) & 1 for j in range(d))
    return bits_to_bytes(bits)


def byte_decode(B: bytes, d: int) -> list[int]:
    """Décode 32·d octets en 256 entiers (ByteDecode_d).

    Pour d = 12, chaque valeur est réduite modulo q (une valeur de
    12 bits peut atteindre 4095 > q) ; pour d < 12 la réduction modulo
    2^d est sans effet.

    Args:
        B: Exactement 32·d octets.
        d: Nombre de bits par coefficient, 1 <= d <= 12.

    Returns:
        256 entiers dans [0, m), m = q si d = 12, sinon 2^d.

    Raises:
        ValueError: Si d est hors bornes ou si len(B) != 32·d.
    """
    if not 1 <= d <= 12:
        raise ValueError("d doit être dans [1, 12]")
    if len(B) != 32 * d:
        raise ValueError(f"{32 * d} octets attendus, {len(B)} reçus")
    m = Q if d == 12 else 1 << d
    bits = bytes_to_bits(B)
    return [
        sum(bits[i * d + j] << j for j in range(d)) % m for i in range(N)
    ]


def compress(x: int, d: int) -> int:
    """Compress_d : Z_q -> Z_{2^d}, arrondi au plus proche.

    Calcule ⌈(2^d / q)·x⌋ mod 2^d en arithmétique entière, avec arrondi
    de la moitié vers le haut : ⌊(2^{d+1}·x + q) / (2q)⌋.

    TODO(verifier) : confirmer dans FIPS 203 la convention d'arrondi
    (demi vers le haut) ; ici elle est dérivée, non copiée.

    Args:
        x: Entier dans [0, q).
        d: Nombre de bits de sortie, 1 <= d < 12.

    Returns:
        Entier dans [0, 2^d).
    """
    # ((x << (d+1)) + Q) // (2Q) == floor(2^d·x/Q + 1/2), sans flottants
    return (((x << (d + 1)) + Q) // (2 * Q)) % (1 << d)


def decompress(y: int, d: int) -> int:
    """Decompress_d : Z_{2^d} -> Z_q, arrondi au plus proche.

    Calcule ⌈(q / 2^d)·y⌋ en arithmétique entière :
    ⌊(2·q·y + 2^d) / 2^{d+1}⌋ = (q·y + 2^{d-1}) >> d.

    TODO(verifier) : confirmer la convention d'arrondi de FIPS 203.

    Args:
        y: Entier dans [0, 2^d).
        d: Nombre de bits d'entrée, 1 <= d < 12.

    Returns:
        Entier dans [0, q).
    """
    return (Q * y + (1 << (d - 1))) >> d


def compress_poly(f: list[int], d: int) -> list[int]:
    """Applique Compress_d à chaque coefficient d'un polynôme.

    Args:
        f: Polynôme (256 entiers dans [0, q)).
        d: Nombre de bits de sortie.

    Returns:
        Polynôme de 256 entiers dans [0, 2^d).
    """
    return [compress(x, d) for x in f]


def decompress_poly(f: list[int], d: int) -> list[int]:
    """Applique Decompress_d à chaque coefficient d'un polynôme.

    Args:
        f: Polynôme (256 entiers dans [0, 2^d)).
        d: Nombre de bits d'entrée.

    Returns:
        Polynôme de 256 entiers dans [0, q).
    """
    return [decompress(y, d) for y in f]
