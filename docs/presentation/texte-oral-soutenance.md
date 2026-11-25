# Texte oral de la soutenance

Généré à partir des notes du présentateur de [DocVault-soutenance.pptx](DocVault-soutenance.pptx) (source : [build-soutenance.js](source/build-soutenance.js)). Les passages entre crochets sont à compléter par l'équipe.

## 1. DocVault

Présentation de l'équipe et du sujet. DocVault est une application de stockage et de partage de documents confidentiels : FastAPI, PostgreSQL, trois rôles (admin, membre, auditeur). Nous l'avons volontairement rendue vulnérable, puis sécurisée à chaque étape de son cycle de vie, avec une preuve pour chaque résultat. [Ajouter la date de la soutenance sur cette diapositive si le format l'exige.]

## 2. Casser, sécuriser, prouver

Notre démarche en trois temps. D'abord casser : nous avons placé sept failles, documentées dans le registre avant toute correction, et un script les exploite toutes en local. Ensuite sécuriser : chaque faille a sa branche et sa pull request, le conteneur et Kubernetes sont durcis, et la CI bloque. Enfin prouver : chaque affirmation de ce rapport renvoie à un run CI, un rapport ou une démonstration. La phrase du bas est le fil rouge de la soutenance.

## 3. Le socle : huit exigences démontrées

Le cahier des charges fixe huit exigences, qui suffisent pour viser vingt sur vingt, à condition d'être démontrées. Les huit sont faites, et le rapport commence par un tableau de conformité qui renvoie chaque exigence à sa preuve. Nous allons les parcourir dans cet ordre.

## 4. Architecture réalisée

Le code part de GitHub vers une étape de sécurité bloquante à cinq contrôles. En cas d'échec, la fusion est refusée. L'application est déployée dans un cluster kind jetable, où Kyverno rejette toute charge non durcie et où le réseau est fermé par défaut. ZAP attaque l'application déployée, et deux couches de détection, les alertes applicatives et Falco, déclenchent le plan de réponse. Précision : le déploiement de test n'attend pas les contrôles statiques, sinon ZAP ne pourrait jamais scanner la version vulnérable ; c'est la fusion dans main qui exige tous les contrôles.

## 5. Ce qui peut mal tourner

Avant d'écrire le code, nous avons fait un modèle de menaces STRIDE : dix-huit menaces sur six actifs, rattachées à l'OWASP Top 10 2025. Le risque principal est l'accès non autorisé aux documents, ce qui explique où nous avons mis le plus d'effort : contrôle d'accès, fichiers, secrets et confinement.

## 6. Sept failles, toutes exploitées

Sept failles couvrant cinq catégories de l'OWASP. Chacune a une preuve d'exploitation : par exemple, Bob télécharge un document privé d'Alice simplement en changeant l'identifiant dans l'URL, c'est F01. Le registre a été écrit avant toute correction, comme l'exige le cahier des charges ; on peut le vérifier dans l'historique Git avec le tag v0-vulnerable. Le script d'exploitation run_all.py les rejoue toutes, et il refuse toute cible autre que localhost.

## 7. Le pipeline bloque, puis laisse passer

Les cinq contrôles exigés tournent en CI depuis des images épinglées par empreinte, avec des seuils écrits et justifiés dans la politique de sécurité : par exemple, tout secret bloque, alors que Trivy ne bloque que sur High ou Critical avec un correctif disponible. La version vulnérable échoue aux cinq, et ces échecs sont gardés comme preuve sur la PR 2. La version corrigée passe les sept contrôles, et main ne peut recevoir qu'une pull request qui les passe tous, même pour un administrateur.

## 8. Chaque outil voit autre chose

C'est notre principal constat. Les outils statiques, Gitleaks, Semgrep, Trivy et Checkov, trouvent quatre failles sur sept. ZAP en ajoute deux, la XSS et la traversée de répertoire, que Semgrep avait manquées. Et F01, l'accès à un document par son identifiant, aucun scanner ne la voit : c'est une faille de logique métier. Seule une suite de tests qui se connecte avec deux utilisateurs la détecte. C'est pour cela que la suite pytest est devenue un contrôle requis.

## 9. Conteneur et Kubernetes durcis

Pour F07, le conteneur tournait en root sur une image complète. L'image est maintenant en deux étapes, sur une base slim épinglée par empreinte, avec un utilisateur dédié. Résultat : zéro vulnérabilité système au lieu de 189, et une image cinq fois plus petite. Dans Kubernetes, chaque pod est non root, en lecture seule, sans capacités ni jeton, et le réseau est fermé par défaut. Kyverno le garantit : à chaque déploiement, nous lui soumettons un pod sans contexte de sécurité, et les quatre politiques le refusent. Il reste deux exceptions Checkov, documentées avec un responsable et une échéance, liées à l'absence de registre d'images.

## 10. DAST authentifié avec ZAP

ZAP tourne dans le pipeline, après le déploiement, et il est authentifié : il se connecte comme alice, en récupérant le jeton CSRF, et vérifie qu'il reste connecté. Sur la version vulnérable, il lève quatre alertes High qui confirment trois failles : l'injection SQL, la XSS et la traversée de répertoire. Le cahier des charges en demandait au moins deux. Sur la version finale, il n'y a plus aucune alerte High ni Medium. Nous avons aussi traité un faux positif : une alerte de traversée sans preuve, écartée après analyse.

## 11. Révoquer d'abord, purger ensuite

La faille F05 était une clé de signature écrite dans le code, et le dépôt est public : il faut la considérer comme connue. Nous avons d'abord révoqué : la clé est fournie à l'exécution, et une session forgée avec l'ancienne clé est refusée. Ensuite seulement nous avons purgé l'historique, avec un script qui travaille sur une copie, vérifie le résultat avec Gitleaks, et refuse de réécrire main. Enfin nous avons vérifié dans un clone neuf. L'ordre compte : purger seul ne sert à rien, car toute copie déjà faite garde la clé ; GitHub garde aussi les anciens commits dans les références des pull requests.

## 12. Détecter pendant l'exécution

La détection a deux couches. L'application écrit ses événements de sécurité en JSON, avec une liste blanche de champs pour ne jamais journaliser de mot de passe ou de cookie, et quatre règles en tirent des alertes. Falco surveille les appels système des conteneurs avec quatre règles propres à DocVault. Le point important : à chaque run CI, deux scripts déclenchent chaque règle de façon inoffensive et vérifient qu'elle s'est bien déclenchée. Et le déploiement échoue si un déploiement normal lève la moindre alerte, ce qui nous protège des règles bruyantes.

## 13. Le plan de réponse, exercé

Le plan de réponse a sept playbooks, chacun avec des commandes réelles, les preuves à garder avant d'agir, et la vérification finale. Nous l'avons exercé sur deux scénarios. P1 : un cookie forgé est détecté en 0,15 seconde ; un cookie volé est contenu en déconnectant un seul utilisateur, puis nous traitons la clé comme exposée et la changeons. P2 : un shell dans le conteneur est détecté par Falco en 0,2 seconde, et le pod est isolé sans détruire les preuves. Soyons honnêtes sur ces temps : ce sont ceux d'un script, pas d'une équipe. Les exercices ont corrigé deux points du plan, notamment qu'après un redémarrage il faut attendre la fin de l'ancien pod.

## 14. Ce que nos contrôles ne prouvent pas

Le rapport consacre un chapitre entier à ce que nos contrôles ne prouvent pas. Les principaux : F01 n'est visible d'aucun scanner ; ZAP ne teste qu'avec un compte, donc pas l'accès d'un utilisateur aux données d'un autre ; il n'y a pas de HTTPS en local ; les tests tournent sur SQLite ; la purge laisse les anciens commits accessibles par les références de pull request jusqu'à une demande au support GitHub ; et l'absence de registre d'images nous a obligés à deux exceptions Checkov, documentées.

## 15. Usage de l'IA, déclaré

Le cahier des charges demande de déclarer tout usage de l'IA. Nous avons utilisé Claude Code, avec le modèle Claude Opus 5.5, et des sous-agents pour certaines parties comme Falco, le plan de réponse et le premier jet du rapport. Chaque production est déclarée dans ai-usage.md, avec ce qui a été vérifié. Aucun résultat n'est repris sans avoir été rejoué : tests, CI, exécution sur un vrai cluster. [Compléter selon l'usage réel de chaque membre, en cohérence avec les fiches Annexe B.]

## 16. Ce que nous retenons

Trois choses à retenir. Chaque couche voit des choses différentes : aucun outil seul n'aurait trouvé les sept failles. Ce qui compte, c'est de pouvoir dire précisément ce que chaque contrôle prouve, et ce qu'il ne prouve pas. Et pour un secret exposé, l'ordre est toujours le même : révoquer d'abord, purger ensuite. Merci, nous répondons à vos questions.
