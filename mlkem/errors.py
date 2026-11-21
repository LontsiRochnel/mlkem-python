"""Exceptions du paquet ``mlkem``.

Rôle dans l'architecture : ce module ne dépend d'aucun autre module du
projet. Il définit les erreurs levées par les contrôles d'entrée de
FIPS 203 (longueurs, validité des clés) et par le choix de la variante.

Remarque : la décapsulation d'un texte chiffré *modifié* ne lève jamais
d'exception (rejet implicite) ; seules les entrées mal formées en
longueur ou les clés invalides sont signalées.
"""


class MLKEMError(Exception):
    """Classe de base de toutes les erreurs du paquet."""


class InvalidVariantError(MLKEMError, ValueError):
    """Variante inconnue, ou taille ne correspondant à aucune variante."""


class InvalidInputLengthError(MLKEMError, ValueError):
    """Entrée de longueur incorrecte (graine, message, aléa...)."""


class InvalidKeyLengthError(MLKEMError, ValueError):
    """Clé d'encapsulation ou de décapsulation de longueur incorrecte."""


class InvalidCiphertextLengthError(MLKEMError, ValueError):
    """Texte chiffré de longueur incorrecte pour la variante."""


class InvalidEncapsulationKeyError(MLKEMError, ValueError):
    """Clé d'encapsulation invalide (échec du contrôle de modulus sur t)."""


class InvalidDecapsulationKeyError(MLKEMError, ValueError):
    """Clé de décapsulation invalide (H(ek) stocké différent de H(ek))."""
