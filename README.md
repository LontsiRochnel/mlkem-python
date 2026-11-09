# mlkem-python

Projet pédagogique autour de ML-KEM, avec une implémentation Python et une interface web entièrement exécutée dans le navigateur.

## Aperçu

- Le cœur cryptographique est implémenté dans le package [mlkem](mlkem).
- La version web repose sur des modules JavaScript dans [web/js/mlkem](web/js/mlkem).
- L’interface utilisateur est servie depuis [web](web) et permet de :
  - générer une paire de clés,
  - encapsuler un secret avec une clé publique,
  - décapsuler avec la clé privée,
  - consulter les données de session dans la page Account.

## Fonctionnement

- Les calculs ML-KEM se font dans le navigateur, sans envoi de clé ou de secret vers un serveur.
- Les données sont conservées localement dans la session du navigateur.
- Le code Python reste utile pour les tests, la validation et les références de conformité.

## Structure du dépôt

- [mlkem](mlkem) : implémentation Python de l’algorithme.
- [web](web) : pages HTML, styles et scripts navigateur.
- [tests](tests) : tests Python et JavaScript de conformité.
- [render.yaml](render.yaml) : configuration de déploiement statique au besoin.
- [LICENSE](LICENSE) : licence du projet.

## Démarrage local

```bash
cd "/Users/lontsirochnel/Desktop/LaTex/Rapport SI/mlkem-python"
python -m mlkem --host 127.0.0.1 --port 8000
```

Puis ouvrir dans le navigateur :

```text
http://127.0.0.1:8000
```

## Vérification

Le projet est validé avec les tests JavaScript et Python :

```bash
cd "/Users/lontsirochnel/Desktop/LaTex/Rapport SI/mlkem-python"
node --test tests/js/*.mjs
python -m pytest
```

## Limites

- Ce projet est pédagogique et non auditée en production.
- Il ne remplace pas une bibliothèque de chiffrement post-quantique validée pour un usage réel.
- Toutes les données de session restent dans le navigateur et ne doivent pas être utilisées pour des clés réelles.

## Licence

Ce projet est distribué sous la licence MIT. Voir [LICENSE](LICENSE).
