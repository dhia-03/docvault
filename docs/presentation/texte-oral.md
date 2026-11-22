# DocVault : texte à dire pour chaque diapositive

Environ 1 minute par diapositive. Sur les diapositives 10 et 14, parler d'« architecture cible » et de « ce que nous allons démontrer » : Kubernetes et ZAP ne sont pas encore en place.

## 1. Titre

Bonjour. Nous sommes Chaima, Sourour, Dhia et Rania, et nous vous présentons DocVault. Notre objectif : prendre une application avec une vraie surface d'attaque et la sécuriser sur tout son cycle de vie, du code jusqu'à la surveillance en production.

## 2. Introduction

DocVault est une application web de stockage et de partage de documents confidentiels. Nous l'avons volontairement construite avec des failles, pour démontrer comment chaque étape du cycle de vie les détecte, les bloque puis les surveille. En résumé : 7 failles volontaires, les 8 exigences du cours à prouver, et une démo en direct. Voici notre plan.

## 3. Contexte

Dans beaucoup de projets, la sécurité arrive trop tard. Les failles naissent dans le code, les dépendances importent des vulnérabilités connues, et un déploiement trop permissif transforme une petite faille en compromission complète. Le DevSecOps répond à ce problème en intégrant la sécurité à chaque étape : coder, construire, tester, déployer et exploiter.

## 4. Problématique

Notre question centrale : comment prouver qu'une application est sûre ? Concrètement, il faut détecter les failles automatiquement avant la production, empêcher le déploiement d'une version non conforme, et repérer une attaque en production pour y répondre. Un pipeline vert ne suffit pas : il faut des preuves.

## 5. Solution proposée

Notre démarche tient en trois temps. D'abord casser : une version vulnérable avec 7 failles documentées et exploitées. Ensuite sécuriser : corrections, pipeline bloquant, conteneur et Kubernetes durcis. Enfin prouver : un scan ZAP avant et après, une détection d'attaque et un plan d'incident répété. En bas, vous voyez l'outil utilisé à chaque étape.

## 6. Les 8 exigences

Voici les 8 exigences obligatoires du cahier des charges, qui suffisent pour viser 20 sur 20 : une application vulnérable, un conteneur sécurisé, une étape bloquante, la gestion des secrets, un déploiement durci, des tests dynamiques, une détection à l'exécution et un plan de réponse aux incidents. Chacune doit être démontrée, pas seulement affirmée.

## 7. L'application

DocVault propose la connexion, le téléversement, la recherche, le téléchargement, le partage et un journal d'audit. Il y a trois rôles : l'administrateur gère les utilisateurs, le membre gère et partage ses documents, et l'auditeur consulte uniquement le journal. Chaque rôle a des limites claires, et c'est ce contrôle d'accès que les attaques cherchent à contourner.

## 8. Les 7 failles

Le cahier des charges demande au moins quatre failles ; nous en avons placé sept, et nous les avons toutes exploitées en local. Par exemple, un membre peut télécharger le document d'un autre en changeant un numéro dans l'adresse, ou extraire les mots de passe par la recherche. La colonne de droite est honnête : en vert, ce qu'un scan réel a vraiment détecté. Résultat important : les outils statiques n'en trouvent que 4 sur 7, d'où la nécessité de plusieurs couches de défense.

## 9. Modèle de menace

Avant de sécuriser, nous avons listé ce qui pouvait mal tourner avec la méthode STRIDE : usurpation, altération, répudiation, divulgation, déni de service et élévation de privilèges. Nous avons identifié 18 menaces. La catégorie la plus importante est la divulgation, logique pour une application de documents confidentiels. Nos failles couvrent cinq catégories de l'OWASP Top 10 2025, et les autres sont traitées par la conception.

## 10. Architecture

Voici l'architecture cible. Le code part de GitHub vers une étape de sécurité bloquante. Si un contrôle échoue, rien n'est déployé. Sinon, l'application est déployée dans un cluster Kubernetes où Kyverno rejette toute charge non durcie et où le réseau est fermé par défaut. ZAP attaque ensuite l'application en marche, et l'observabilité détecte les attaques pour déclencher le plan de réponse.

## 11. Pipeline CI

Le cœur du projet est l'étape bloquante, avec cinq contrôles : le code avec Semgrep, les dépendances et l'image avec Trivy, les secrets avec Gitleaks, et les fichiers de déploiement avec Checkov. Une politique écrite et justifiée décide du résultat. En cas d'échec, rien n'est déployé et l'échec sert de preuve. En cas de succès, on déploie dans un environnement de test, on vérifie que l'application répond, puis on lance le scan ZAP authentifié.

## 12. Avancement

Voici où nous en sommes. Les 7 failles sont exploitées en local, 3 des 5 contrôles de la CI sont actifs, et 18 menaces sont analysées. Le dépôt, la politique de blocage et l'application vulnérable sont prêts. Il reste à ajouter le scan d'image et Checkov, le déploiement Kubernetes durci, le scan ZAP, puis les corrections et la détection.

## 13. Planning

Le projet suit dix étapes, de la réservation du thème jusqu'au rendu. Les trois premières sont faites ou rédigées, la quatrième est en cours, et les six suivantes sont à faire. L'ordre est important : nous documentons chaque faille avant de la corriger, comme l'exige le cahier des charges. Les dates seront fixées dès que la date de rendu sera connue.

## 14. Démo

La démo suit sept étapes. Nous exploitons d'abord les failles, puis nous poussons un secret de test et la CI échoue. Après les correctifs, la CI passe. Nous déployons sur Kubernetes, Kyverno rejette une charge non durcie, et nous comparons les scans ZAP avant et après. Enfin, nous rejouons une attaque, la retrouvons dans Grafana, et déroulons le plan de réponse.

## 15. Organisation

Chaque membre porte une étape du cycle de vie : M1 l'application et ses failles, M2 la CI et les secrets, M3 le conteneur, Kubernetes et le scan ZAP, M4 l'observabilité, la détection et la coordination du rapport. Comme l'exige le cahier des charges.

## 16. Conclusion

Pour conclure, un pipeline qui passe ne prouve pas qu'une application est sûre. C'est pourquoi chaque contrôle s'accompagne d'une preuve, et chaque limite est documentée, comme les failles que Semgrep ne détecte pas. Merci de votre attention, nous sommes prêts pour vos questions.
