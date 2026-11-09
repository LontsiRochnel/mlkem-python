# mlkem-python

Projet pédagogique Python pour illustrer le mécanisme d'encapsulation de clés ML-KEM, conforme dans l'esprit au standard NIST FIPS 203 (août 2024), sans prétendre être une implémentation de production auditable.

> AVERTISSEMENT : ce code est fourni à des fins d'enseignement et de recherche. Il n'a pas été audité, n'est pas examiné par un comité de sécurité, et ne doit pas être utilisé en production sans revue indépendante, tests de sécurité et validations de conformité complètes. En particulier, la clé privée `dk` ne doit jamais être envoyée à un serveur non protégé ; l'exposition HTTP de `decaps` est strictement pédagogique. Il n'y a ni TLS ni authentification et le serveur est sans état.

## Objectif

Le module `mlkem` expose une API publique simple permettant à Alice et Bob d'utiliser ML-KEM via des fonctions lisibles et documentées :

- `keygen(variant="ML-KEM-768")`
- `encaps(ek, variant=None)`
- `decaps(dk, c, variant=None)`

La structure est pensée pour être didactique : les étapes de K-PKE puis de ML-KEM sont séparées, avec des docstrings détaillées et un code orienté vers la pédagogie.

## Installation

```bash
cd mlkem-python
python -m pip install -e .
```

## Utilisation rapide

```python
from mlkem import keygen, encaps, decaps

# Bob génère ses clés
ek, dk = keygen("ML-KEM-768")

# Alice encapsule le secret partagé pour Bob
K_a, c = encaps(ek, "ML-KEM-768")

# Bob découpe le secret partagé
K_b = decaps(dk, c, "ML-KEM-768")

print(K_a == K_b)
```

Le script `examples/alice_bob.py` montre le même scénario complet avec messages simples entre Alice et Bob.

## Exécution de l'exemple

```bash
cd mlkem-python
python examples/alice_bob.py
```

## Serveur HTTP

Le projet expose une API HTTP simple via le module [mlkem/server.py](mlkem/server.py). Le serveur est sans état, ne conserve aucune clé entre deux requêtes, et n'implémente ni TLS ni authentification.

### Lancement

```bash
cd mlkem-python
python -m mlkem --host 127.0.0.1 --port 8000
```

ou via le point d'entrée console :

```bash
cd mlkem-python
mlkem-server --host 127.0.0.1 --port 8000
```

> Si l'utilisateur choisit `0.0.0.0`, le serveur affiche un avertissement explicite car il écoute sur toutes les interfaces réseau. Ce mode est uniquement utile pour du test local, pas pour un déploiement réel.

### Routes

| Méthode | Route        | Description                       | Exemple curl                                                                                                                          |
| ------- | ------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| GET     | `/health`    | Vérifie que le service répond     | `curl http://127.0.0.1:8000/health`                                                                                                   |
| GET     | `/v1/params` | Retourne les variantes et tailles | `curl http://127.0.0.1:8000/v1/params`                                                                                                |
| POST    | `/v1/keygen` | Génère `ek` et `dk`               | `curl -X POST -H 'Content-Type: application/json' -d '{"variant":"ML-KEM-768"}' http://127.0.0.1:8000/v1/keygen`                      |
| POST    | `/v1/encaps` | Encapsule depuis `ek`             | `curl -X POST -H 'Content-Type: application/json' -d '{"ek":"...","variant":"ML-KEM-768"}' http://127.0.0.1:8000/v1/encaps`           |
| POST    | `/v1/decaps` | Décapsule depuis `dk` et `c`      | `curl -X POST -H 'Content-Type: application/json' -d '{"dk":"...","c":"...","variant":"ML-KEM-768"}' http://127.0.0.1:8000/v1/decaps` |

### Exemple de réponses

```json
{ "status": "ok" }
```

```json
{ "ek": "...", "dk": "..." }
```

```json
{ "K": "...", "c": "..." }
```

## Client HTTP

Le script [examples/client_http.py](examples/client_http.py) montre un scénario complet Alice/Bob en passant par le serveur HTTP local.

```bash
cd mlkem-python
python examples/client_http.py
```

Le client appelle :

1. `POST /v1/keygen` côté Bob
2. `POST /v1/encaps` côté Alice
3. `POST /v1/decaps` côté Bob
4. vérifie que `K_A == K_B`

## Interface web

Une interface web pédagogique est aussi disponible dans le dossier [web](web). Pour la lancer :

```bash
cd mlkem-python
python -m mlkem --host 127.0.0.1 --port 8000
```

Puis ouvrez dans un navigateur :

```text
http://127.0.0.1:8000
```

L'interface propose :

- génération de clés ML-KEM,
- sauvegarde dans `sessionStorage`,
- encapsulation d'un secret pour une clé publique,
- décapsulation d'un texte reçu,
- consultation des clés et de l'historique dans la page « Mes infos ».

> La session est perdue à la fermeture de l'onglet. Cette interface est pédagogique et ne doit pas être utilisée pour stocker de vraies clés privées.

## Lancement des tests

```bash
cd mlkem-python
python -m pytest
```

## Correspondance FIPS 203

| Fonction / module                | Algorithme                  | Section / référence                          |
| -------------------------------- | --------------------------- | -------------------------------------------- |
| `mlkem.kem.ML-KEM.KeyGen`        | ML-KEM.KeyGen               | Algorithme ML-KEM.KeyGen, TODO(verifier)     |
| `mlkem.kem.ML-KEM.Encaps`        | ML-KEM.Encaps               | Algorithme ML-KEM.Encaps, TODO(verifier)     |
| `mlkem.kem.ML-KEM.Decaps`        | ML-KEM.Decaps               | Algorithme ML-KEM.Decaps, TODO(verifier)     |
| `mlkem.kpke.K-PKE.KeyGen`        | K-PKE.KeyGen                | Algorithme K-PKE.KeyGen, TODO(verifier)      |
| `mlkem.kpke.K-PKE.Encrypt`       | K-PKE.Encrypt               | Algorithme K-PKE.Encrypt, TODO(verifier)     |
| `mlkem.kpke.K-PKE.Decrypt`       | K-PKE.Decrypt               | Algorithme K-PKE.Decrypt, TODO(verifier)     |
| `mlkem.encoding.ByteEncode_d`    | Encodage de polynômes       | FIPS 203, encodage de coefficients et octets |
| `mlkem.encoding.ByteDecode_d`    | Décodage de polynômes       | FIPS 203, décodage de coefficients et octets |
| `mlkem.encoding.Compress_d`      | Compression / décompression | FIPS 203, compression des coefficients       |
| `mlkem.encoding.Decompress_d`    | Compression / décompression | FIPS 203, décompression des coefficients     |
| `mlkem.sampling.SampleNTT`       | Échantillonnage NTT         | FIPS 203, génération de polynômes étendu     |
| `mlkem.sampling.SamplePolyCBD_η` | CBD                         | FIPS 203, échantillonnage de bruit           |
| `mlkem.sampling.PRF`             | PRF                         | FIPS 203, fonction de dérivation             |

> Les vecteurs KAT officiels ACVP / NIST ne sont pas inclus dans ce dépôt. À ajouter plus tard pour validation de conformité exhaustive.

## Références

- National Institute of Standards and Technology (NIST), FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard, août 2024.
- Bos, J., Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schanck, J. M., Schwabe, P., Seiler, G. et Stehlé, D. (2018). CRYSTALS-Kyber: a CCA-secure module-lattice-based KEM.

## Licence

Ce projet est distribué sous la licence MIT. Voir [LICENSE](LICENSE).
