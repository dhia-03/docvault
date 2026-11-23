# DocVault : point d'avancement

**Date :** 18/11/2026
**Équipe :** Chaima Khaalsi, Sourour Kraiem, Dhia Medhioub, Rania Khalfet
**Thème proposé :** DocVault, une application de stockage et de partage de documents confidentiels (validation demandée)

## Critère de validité

| Élément exigé | Dans DocVault |
| --- | --- |
| Backend | FastAPI (Python) |
| Base de données | PostgreSQL |
| Authentification à rôles | Administrateur, membre, auditeur |
| Données sensibles | Documents confidentiels, empreintes de mots de passe |

## Travail réalisé

- **Dépôt GitHub privé** (`dhia-03/docvault`) avec la structure du projet.
- **Pipeline d'intégration continue** (GitHub Actions) avec trois des cinq contrôles exigés : détection de secrets avec caviardage (Gitleaks), analyse statique (Semgrep) et analyse des dépendances (Trivy). Les outils sont épinglés à une version précise. Le blocage a été vérifié en local sur un secret, une injection de commande et une dépendance vulnérable.
- **Modèle de menace** STRIDE (18 menaces), avec une cartographie OWASP Top 10:2025.
- **Politique de blocage écrite**, avec les seuils, les exceptions tolérées et leurs échéances, et la justification de chaque choix.
- **Application volontairement vulnérable**, fonctionnelle en local, avec 7 failles documentées avant correction (emplacement, cause, impact). Les 7 ont été exploitées en local par un script de preuve qui refuse toute cible autre que la machine locale.

| Faille | OWASP 2025 | Détectée par les outils actuels |
| --- | --- | --- |
| F01 Accès à un document d'autrui par son identifiant | A01 | Non |
| F02 Injection SQL dans la recherche | A05 | Semgrep |
| F03 Script injecté (XSS) | A05 | Non |
| F04 Traversée de répertoire | A01 | Non |
| F05 Clé de signature écrite dans le code (valeur de test) | A07 | Gitleaks |
| F06 Dépendance vulnérable (PyYAML 5.3) | A03 | Trivy |
| F07 Conteneur exécuté en root | A02 | Semgrep |

Les outils statiques ne trouvent que 4 failles sur 7. Ce constat sera repris dans la réflexion critique du rapport.

## Prochaines étapes

1. Pousser la version vulnérable et conserver l'échec du pipeline comme preuve.
2. Compléter l'étape de sécurité avec l'analyse de l'image et des fichiers de déploiement (Checkov).
3. Déployer sur Kubernetes (Minikube) avec durcissement, segmentation réseau et Kyverno.
4. Intégrer un scan OWASP ZAP authentifié dans le pipeline, après le déploiement.
5. Corriger chaque faille, faire la démonstration « révoquer d'abord, purger ensuite », ajouter la détection d'attaque et le plan de réponse, puis rédiger le rapport.

## Questions

1. Le thème DocVault est-il validé ?
2. Quelle est la date de rendu ? Les sections 7 et 8 sont absentes du document.
3. À quel compte GitHub dois-je donner accès au dépôt privé ?

## Usage d'outils d'IA

L'équipe utilise Claude Code (Anthropic) pour la conception, le code et la documentation. Comme l'exige le cahier des charges, chaque élément produit et sa validation sont consignés dans `docs/ai-usage.md`.
