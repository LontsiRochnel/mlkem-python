"""Exemple pédagogique d'interaction Alice / Bob avec ML-KEM."""

from mlkem import decaps, encaps, keygen


def main() -> None:
    """Démontre un échange de clés classique Alice / Bob."""
    variant = "ML-KEM-768"
    print(f"[Bob] Génération des clés ({variant})")
    ek, dk = keygen(variant)
    print(f"[Bob] ek: {len(ek)} octets, dk: {len(dk)} octets")

    print("[Alice] Encapsulation du secret partagé")
    K_a, c = encaps(ek, variant)
    print(f"[Alice] K_A: {len(K_a)} octets, c: {len(c)} octets")

    print("[Bob] Décapsulation du secret partagé")
    K_b = decaps(dk, c, variant)
    print(f"[Bob] K_B: {len(K_b)} octets")

    print(f"[Résultat] K_A == K_B ? {K_a == K_b}")
    print(
        "[Note] Ensuite, K sert de clé symétrique pour un chiffrement de flux ou AEAD."
    )


if __name__ == "__main__":
    main()
