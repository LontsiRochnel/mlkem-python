"""Démo ML-KEM : Bob génère ses clés, Alice encapsule, Bob décapsule.

Usage (depuis la racine du dépôt) : python examples/alice_bob.py [VARIANTE]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # import sans installation

import mlkem  # noqa: E402

variant = sys.argv[1] if len(sys.argv) > 1 else "ML-KEM-768"

# Bob : génère (ek, dk), publie ek, garde dk secret.
ek, dk = mlkem.keygen(variant)
print(f"[Bob]   {variant} : ek={len(ek)} o, dk={len(dk)} o")

# Alice : encapsule sous ek ; garde K, envoie c.
K_alice, c = mlkem.encaps(ek)
print(f"[Alice] c={len(c)} o, K={K_alice.hex()}")

# Bob : décapsule c avec dk.
K_bob = mlkem.decaps(dk, c)
print(f"[Bob]   K={K_bob.hex()}")
print("Clés identiques :", K_alice == K_bob)

# Texte modifié : pas d'erreur, mais une clé différente (rejet implicite).
bad = bytes([c[0] ^ 1]) + c[1:]
print("Texte modifié -> clé différente :", mlkem.decaps(dk, bad) != K_alice)
