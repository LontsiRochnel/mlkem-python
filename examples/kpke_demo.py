"""Démo K-PKE seul : chiffrement d'un message de 32 octets.

Usage (depuis la racine du dépôt) : python examples/kpke_demo.py

Attention : K-PKE seul n'est pas sûr contre les attaques à chiffré
choisi ; c'est ML-KEM (transformation de Fujisaki-Okamoto) qui l'est.
"""

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # import sans installation

from mlkem.kpke import kpke_decrypt, kpke_encrypt, kpke_keygen  # noqa: E402

variant = "ML-KEM-768"
ek_pke, dk_pke = kpke_keygen(secrets.token_bytes(32), variant)

message = b"Message de 32 octets exactement!"
assert len(message) == 32

c = kpke_encrypt(ek_pke, message, secrets.token_bytes(32), variant)
recovered = kpke_decrypt(dk_pke, c, variant)

print(f"variante      : {variant}")
print(f"ek_PKE / dk_PKE / c : {len(ek_pke)} / {len(dk_pke)} / {len(c)} octets")
print(f"message       : {message!r}")
print(f"déchiffré     : {recovered!r}")
print("OK" if recovered == message else "ÉCHEC")
