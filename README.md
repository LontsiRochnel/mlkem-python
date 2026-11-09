# mlkem-python

Projet pédagogique pour illustrer ML-KEM, avec une interface web entièrement statique et un noyau JavaScript pur exécuté dans le navigateur.

> La version navigateur ne doit pas être utilisée pour protéger des données réelles. Le code est pédagogique, non audité, et ne garantit ni sécurité side-channel ni temps constant. Pour un usage réel, utiliser une bibliothèque auditée comme @noble/post-quantum ou liboqs.

## Fonctionnement

- Le calcul ML-KEM se fait dans le navigateur via les modules de [web/js/mlkem](web/js/mlkem).
- Le fichier [web/js/api.js](web/js/api.js) appelle directement les fonctions JavaScript, sans `fetch`, `XMLHttpRequest` ni WebSocket.
- Le serveur Python ne sert que les fichiers statiques du dossier [web](web) en local.
- Les routes `/v1/*` restent disponibles pour les tests Python, mais la page web ne les utilise plus.

### Démarrage local

```bash
cd "/Users/lontsirochnel/Desktop/LaTex/Rapport SI/mlkem-python"
python -m mlkem --host 127.0.0.1 --port 8000
```

Puis ouvrir dans le navigateur :

```text
http://127.0.0.1:8000
```

### Vérification réseau

1. Ouvrir les outils de développement.
2. Aller dans l’onglet Réseau.
3. Effectuer une génération de clés, une encapsulation ou une décapsulation.
4. Aucune requête réseau ne doit apparaître.

## Vérification

La conformité croisée est vérifiée avec les vecteurs Python générés dans [tests/js/fixtures.json](tests/js/fixtures.json).

```bash
cd "/Users/lontsirochnel/Desktop/LaTex/Rapport SI/mlkem-python"
python tests/js/generate_fixtures.py
node --test tests/js/
python -m pytest
```

## Tests

```bash
cd "/Users/lontsirochnel/Desktop/LaTex/Rapport SI/mlkem-python"
node --test tests/js/
python -m pytest
```

## Déploiement Render

Le site est statique. Le fichier [render.yaml](render.yaml) pointe vers le dossier [web](web) et applique des en-têtes de sécurité :

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

### Procédure

1. Créer un service Render de type `static`.
2. Définir `staticPublishPath: web`.
3. Déployer le dépôt GitHub.
4. Vérifier que la page s’affiche sans appel réseau.

## Limites

- Implémentation pédagogique, non auditée.
- Le code pur JavaScript n’offre pas de garantie de temps constant ou de résistance à des attaques par canaux auxiliaires.
- Pour un usage réel, utiliser une bibliothèque auditée comme @noble/post-quantum ou liboqs.

## Correspondance FIPS 203

- Algorithme ML-KEM.KeyGen, TODO(verifier)
- Algorithme ML-KEM.Encaps, section 6.2, TODO(verifier)
- Algorithme ML-KEM.Decaps, TODO(verifier)
- Algorithme K-PKE.KeyGen, TODO(verifier)
- Algorithme K-PKE.Encrypt, TODO(verifier)
- Algorithme K-PKE.Decrypt, TODO(verifier)
- ByteEncode_d, TODO(verifier)
- ByteDecode_d, TODO(verifier)
- Compress_d, TODO(verifier)
- Decompress_d, TODO(verifier)
- SampleNTT, TODO(verifier)
- SamplePolyCBD_eta, TODO(verifier)
- PRF, TODO(verifier)

## Licence

Ce projet est distribué sous la licence MIT. Voir [LICENSE](LICENSE).
