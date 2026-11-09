"""Exceptions spécifiques au mécanisme ML-KEM.

L'API pédagogique lève des exceptions explicites lors d'un échec de contrôle
entrée, afin d'indiquer précisément si la clé ou le texte encapsulé est
invalide.
"""


class InvalidSizeError(ValueError):
    """Exception levée lorsqu'une taille ou une variante n'est pas valide."""


class InvalidKeyError(ValueError):
    """Exception levée lorsqu'une clé publique ou privée est invalide."""


class InvalidCiphertextError(ValueError):
    """Exception levée lorsqu'un texte encapsulé est invalide."""
