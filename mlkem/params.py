"""Paramètres de ML-KEM : constantes communes et trois variantes.

Rôle dans l'architecture (1/3 : paramètres, puis K-PKE, puis ML-KEM) :
ce module est la base de tout le projet. Il contient les constantes
communes (q, n, ζ) et les jeux de paramètres (k, η1, η2, du, dv) de
ML-KEM-512, ML-KEM-768 et ML-KEM-1024, avec les tailles en octets qui en
découlent. Les tailles sont *calculées* à partir des paramètres ; les
tests les comparent aux valeurs publiées.
"""

from dataclasses import dataclass

from .errors import InvalidVariantError

Q = 3329
"""Module premier q = 3329 (entiers, sans unité)."""

N = 256
"""Nombre de coefficients d'un polynôme de R_q = Z_q[X]/(X^256 + 1)."""

ZETA = 17
"""Racine 256-ième primitive de l'unité modulo q (ζ = 17)."""


@dataclass(frozen=True)
class Params:
    """Jeu de paramètres d'une variante de ML-KEM.

    Attributes:
        name: Nom de la variante, par exemple ``"ML-KEM-768"``.
        k: Nombre de polynômes dans un vecteur (dimension du module).
        eta1: Paramètre η1 de la loi binomiale centrée (bruit de s, e, y).
        eta2: Paramètre η2 de la loi binomiale centrée (bruit e1, e2).
        du: Nombre de bits de compression des coefficients de u.
        dv: Nombre de bits de compression des coefficients de v.
    """

    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int

    @property
    def ek_size(self) -> int:
        """Taille de la clé d'encapsulation en octets : 384k + 32."""
        return 384 * self.k + 32

    @property
    def dk_pke_size(self) -> int:
        """Taille de dk_PKE en octets : 384k."""
        return 384 * self.k

    @property
    def dk_size(self) -> int:
        """Taille de la clé de décapsulation en octets : 768k + 96.

        Composition : dk_PKE (384k) || ek (384k+32) || H(ek) (32) || z (32).
        """
        return 768 * self.k + 96

    @property
    def c_size(self) -> int:
        """Taille du texte chiffré en octets : 32(du·k + dv)."""
        return 32 * (self.du * self.k + self.dv)

    @property
    def K_size(self) -> int:
        """Taille de la clé partagée en octets (32 pour toutes les variantes)."""
        return 32


ML_KEM_512 = Params("ML-KEM-512", k=2, eta1=3, eta2=2, du=10, dv=4)
ML_KEM_768 = Params("ML-KEM-768", k=3, eta1=2, eta2=2, du=10, dv=4)
ML_KEM_1024 = Params("ML-KEM-1024", k=4, eta1=2, eta2=2, du=11, dv=5)

VARIANTS = {p.name: p for p in (ML_KEM_512, ML_KEM_768, ML_KEM_1024)}


def get_params(variant) -> Params:
    """Résout une variante donnée par son nom ou par un objet ``Params``.

    Args:
        variant: ``Params`` ou chaîne (``"ML-KEM-512"``, ``"ML-KEM-768"``,
            ``"ML-KEM-1024"``).

    Returns:
        Le jeu de paramètres correspondant.

    Raises:
        InvalidVariantError: Si la variante est inconnue.
    """
    if isinstance(variant, Params):
        return variant
    if isinstance(variant, str) and variant in VARIANTS:
        return VARIANTS[variant]
    raise InvalidVariantError(f"variante inconnue : {variant!r}")


def params_from_ek_size(size: int) -> Params:
    """Déduit la variante de la taille d'une clé d'encapsulation.

    Args:
        size: Longueur de ek en octets.

    Returns:
        Le jeu de paramètres dont ``ek_size`` vaut ``size``.

    Raises:
        InvalidVariantError: Si aucune variante ne correspond.
    """
    for p in VARIANTS.values():
        if p.ek_size == size:
            return p
    raise InvalidVariantError(f"taille de ek ({size} octets) inconnue")


def params_from_dk_size(size: int) -> Params:
    """Déduit la variante de la taille d'une clé de décapsulation.

    Args:
        size: Longueur de dk en octets.

    Returns:
        Le jeu de paramètres dont ``dk_size`` vaut ``size``.

    Raises:
        InvalidVariantError: Si aucune variante ne correspond.
    """
    for p in VARIANTS.values():
        if p.dk_size == size:
            return p
    raise InvalidVariantError(f"taille de dk ({size} octets) inconnue")
