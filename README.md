# mlkem-python

Implémentation **pédagogique** de ML-KEM (FIPS 203, août 2024) et de son
sous-schéma K-PKE, en Python 3.10+ pur (bibliothèque standard uniquement :
`hashlib`, `hmac`, `secrets`, `dataclasses`). Variantes : ML-KEM-512, 768, 1024.

## Avertissements (à lire)

- Projet pédagogique, **non audité**, **à ne pas utiliser en production**.
- **Aucune protection contre les canaux auxiliaires** : Python n'est pas à temps
  constant. Seule la comparaison finale du chiffré recalculé utilise
  `hmac.compare_digest`.
- Pour un usage réel, utiliser une bibliothèque auditée (par exemple liboqs).
- **Conformité non démontrée** : les vecteurs de test officiels (ACVP / NIST)
  n'étaient pas disponibles lors du développement et n'ont pas été inventés.
  Les tests ne vérifient que la cohérence interne (tailles, aller-retours,
  rejet implicite, produit NTT = produit naïf). Sans ces vecteurs, on ne peut
  pas affirmer que l'implémentation est conforme au standard (voir « Travail restant »).

## Utilisation

```python
import mlkem
ek, dk = mlkem.keygen("ML-KEM-768")   # Bob
K, c = mlkem.encaps(ek)               # Alice : variante déduite de len(ek)
assert mlkem.decaps(dk, c) == K       # Bob : variante déduite de len(dk)
```

K-PKE seul : `from mlkem.kpke import kpke_keygen, kpke_encrypt, kpke_decrypt`
(voir `examples/kpke_demo.py`). Un chiffré ML-KEM modifié ne lève aucune
exception : `decaps` renvoie J(z || c) (rejet implicite).

```
python examples/alice_bob.py [ML-KEM-512|ML-KEM-768|ML-KEM-1024]
python examples/kpke_demo.py
pip install pytest && python -m pytest
```

## Correspondance code / FIPS 203

Les noms sont ceux de FIPS 203 ; aucun numéro d'algorithme ou de section n'est
cité (non vérifiable ici, voir TODO).

| Fonction du code | Algorithme de FIPS 203 | Fichier |
|---|---|---|
| `bits_to_bytes` | BitsToBytes | `mlkem/encoding.py` |
| `bytes_to_bits` | BytesToBits | `mlkem/encoding.py` |
| `byte_encode` | ByteEncode_d | `mlkem/encoding.py` |
| `byte_decode` | ByteDecode_d | `mlkem/encoding.py` |
| `compress` / `decompress` | Compress_d / Decompress_d | `mlkem/encoding.py` |
| `sample_ntt` | SampleNTT | `mlkem/sampling.py` |
| `sample_poly_cbd` | SamplePolyCBD_η | `mlkem/sampling.py` |
| `H`, `G`, `J`, `prf`, `xof_input` | H, G, J, PRF_η, XOF | `mlkem/sampling.py` |
| `ntt` | NTT | `mlkem/arith.py` |
| `ntt_inv` | NTT inverse | `mlkem/arith.py` |
| `base_case_multiply` | BaseCaseMultiply | `mlkem/arith.py` |
| `multiply_ntts` | MultiplyNTTs | `mlkem/arith.py` |
| `kpke_keygen` | K-PKE.KeyGen | `mlkem/kpke.py` |
| `kpke_encrypt` | K-PKE.Encrypt | `mlkem/kpke.py` |
| `kpke_decrypt` | K-PKE.Decrypt | `mlkem/kpke.py` |
| `keygen_internal` | ML-KEM.KeyGen_internal | `mlkem/kem.py` |
| `encaps_internal` | ML-KEM.Encaps_internal | `mlkem/kem.py` |
| `decaps_internal` | ML-KEM.Decaps_internal (FO, rejet implicite) | `mlkem/kem.py` |
| `keygen` | ML-KEM.KeyGen | `mlkem/kem.py` |
| `encaps` | ML-KEM.Encaps (+ contrôle de ek) | `mlkem/kem.py` |
| `decaps` | ML-KEM.Decaps (+ contrôles de dk et de c) | `mlkem/kem.py` |
| `check_encapsulation_key` | Contrôle d'entrée de ek (aller-retour sur t) | `mlkem/kem.py` |
| `check_decapsulation_key` | Contrôle d'entrée de dk (H(ek) stocké) | `mlkem/kem.py` |

Les tables ζ^BitRev7(i) et ζ^(2·BitRev7(i)+1) sont calculées, non recopiées.

## Travail restant

- **Vecteurs ACVP / NIST** : à ajouter (tests de KeyGen_internal, Encaps_internal,
  Decaps). Tant qu'ils ne passent pas, la conformité n'est pas établie.
- Points marqués `TODO(verifier)` dans le code, à confronter au texte de FIPS 203 :
  1. `encoding.compress` : convention d'arrondi (demi vers le haut) dérivée, non copiée.
  2. `encoding.decompress` : idem.
  3. `sampling.xof_input` : ordre des octets d'indices (ρ || j || i) pour A[i][j].
  4. `kpke.kpke_keygen` : dérivation (ρ, σ) = G(d || k) avec l'octet k.
  5. Numéros d'algorithmes et de sections : volontairement non cités.
- Les tests ont été exécutés avec un lanceur provisoire (pytest indisponible dans
  l'environnement de rédaction) : relancer `python -m pytest` chez vous.
