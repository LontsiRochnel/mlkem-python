# mlkem-python

Implémentation **pédagogique** de ML-KEM (FIPS 203, août 2024) et de son
sous-schéma K-PKE, en Python 3.10+ pur. Seule la bibliothèque standard est
utilisée (`hashlib`, `hmac`, `secrets`, `dataclasses`). Variantes : ML-KEM-512,
ML-KEM-768 et ML-KEM-1024.

## Conformité

L'implémentation est vérifiée par les vecteurs de test officiels du NIST (ACVP),
révision FIPS203-tr1 pour l'encapsulation et la décapsulation :

| Jeu de vecteurs                        | Cas | Résultat |
| -------------------------------------- | --- | -------- |
| Génération de clés (`KeyGen_internal`) | 75  | réussis  |
| Encapsulation (`Encaps_internal`)      | 75  | réussis  |
| Décapsulation                          | 60  | réussis  |
| Contrôles de clés (`ek` et `dk`)       | 60  | réussis  |

Les trois variantes sont couvertes. Les tests de cohérence interne (tailles,
aller-retours, rejet implicite, NTT) passent également.

## Avertissements

- Projet pédagogique, **non audité**, **à ne pas utiliser en production**.
- **Aucune protection contre les attaques par canaux auxiliaires** : Python n'est
  pas à temps constant. Seule la comparaison finale du chiffré recalculé utilise
  `hmac.compare_digest`.
- Pour un usage réel, utiliser une bibliothèque auditée, par exemple liboqs.

## Installation

```
python -m pip install -e .
```

Pour les tests : `pip install pytest`.

## Utilisation

```python
import mlkem

ek, dk = mlkem.keygen("ML-KEM-768")   # Bob génère ses clés
K, c = mlkem.encaps(ek)               # Alice encapsule (variante déduite de len(ek))
assert mlkem.decaps(dk, c) == K       # Bob décapsule (variante déduite de len(dk))
```

Un texte encapsulé modifié ne lève aucune exception : `decaps` renvoie
J(z || c), c'est le rejet implicite.

K-PKE s'utilise seul :

```python
from mlkem.kpke import kpke_keygen, kpke_encrypt, kpke_decrypt
```

Exemples :

```
python examples/alice_bob.py [ML-KEM-512|ML-KEM-768|ML-KEM-1024]
python examples/kpke_demo.py
```

## Tests

```
python -m pytest
```

- `tests/test_arith.py`, `test_encoding.py`, `test_sampling.py` : briques élémentaires.
- `tests/test_kpke.py`, `test_kem.py`, `test_sizes.py` : cohérence interne.
- `tests/test_kat.py` : encapsulation, décapsulation et contrôles de clés, sur les
  vecteurs NIST placés dans `tests/vectors/ML-KEM-encapDecap-FIPS203-tr1/`.
- `tests/test_keygen_kat.py` : génération de clés, sur les vecteurs placés dans
  `tests/vectors/ML-KEM-keyGen-FIPS203/`.

Les vecteurs proviennent du dépôt ACVP-Server du NIST
(`gen-val/json-files/`).

## Structure du projet

```
mlkem/
├── __init__.py   API publique : keygen, encaps, decaps
├── params.py     paramètres des variantes et tailles
├── arith.py      arithmétique modulo q, NTT, NTT inverse
├── encoding.py   encodage, décodage, compression
├── sampling.py   SampleNTT, SamplePolyCBD, PRF, XOF
├── kpke.py       K-PKE
├── kem.py        ML-KEM, Fujisaki-Okamoto, rejet implicite
└── errors.py     exceptions des contrôles d'entrée
```

## Correspondance code / FIPS 203

Les noms sont ceux de FIPS 203.

| Fonction du code                      | Algorithme de FIPS 203                                     | Fichier             |
| ------------------------------------- | ---------------------------------------------------------- | ------------------- |
| `bits_to_bytes`, `bytes_to_bits`      | BitsToBytes, BytesToBits                                   | `mlkem/encoding.py` |
| `byte_encode`, `byte_decode`          | ByteEncode_d, ByteDecode_d                                 | `mlkem/encoding.py` |
| `compress`, `decompress`              | Compress_d, Decompress_d                                   | `mlkem/encoding.py` |
| `sample_ntt`                          | SampleNTT                                                  | `mlkem/sampling.py` |
| `sample_poly_cbd`                     | SamplePolyCBD_η                                            | `mlkem/sampling.py` |
| `H`, `G`, `J`, `prf`, `xof_input`     | H, G, J, PRF_η, XOF                                        | `mlkem/sampling.py` |
| `ntt`, `ntt_inv`                      | NTT, NTT inverse                                           | `mlkem/arith.py`    |
| `base_case_multiply`, `multiply_ntts` | BaseCaseMultiply, MultiplyNTTs                             | `mlkem/arith.py`    |
| `kpke_keygen`                         | K-PKE.KeyGen                                               | `mlkem/kpke.py`     |
| `kpke_encrypt`                        | K-PKE.Encrypt                                              | `mlkem/kpke.py`     |
| `kpke_decrypt`                        | K-PKE.Decrypt                                              | `mlkem/kpke.py`     |
| `keygen_internal`                     | ML-KEM.KeyGen_internal                                     | `mlkem/kem.py`      |
| `encaps_internal`                     | ML-KEM.Encaps_internal                                     | `mlkem/kem.py`      |
| `decaps_internal`                     | ML-KEM.Decaps_internal (Fujisaki-Okamoto, rejet implicite) | `mlkem/kem.py`      |
| `keygen`                              | ML-KEM.KeyGen                                              | `mlkem/kem.py`      |
| `encaps`                              | ML-KEM.Encaps, avec contrôle de ek                         | `mlkem/kem.py`      |
| `decaps`                              | ML-KEM.Decaps, avec contrôles de dk et de c                | `mlkem/kem.py`      |
| `check_encapsulation_key`             | contrôle d'entrée de ek                                    | `mlkem/kem.py`      |
| `check_decapsulation_key`             | contrôle d'entrée de dk (H(ek) stocké)                     | `mlkem/kem.py`      |

Les tables ζ^BitRev7(i) et ζ^(2·BitRev7(i)+1) sont calculées à l'exécution, non
recopiées.

## Licence

MIT, voir `LICENSE`.
