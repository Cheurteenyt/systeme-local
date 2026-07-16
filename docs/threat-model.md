# Modèle de menace

## Actifs à protéger

- fichiers personnels et professionnels ;
- secrets, clés API, cookies et jetons Git ;
- intégrité du système hôte ;
- confidentialité des prompts, modèles et jeux de données ;
- budget GPU/CPU, API et tokens ;
- dépôts Git et chaîne de publication.

## Menaces principales

1. Prompt injection contenue dans une page, un dépôt ou une sortie de modèle.
2. Tâche falsifiée, rejouée ou modifiée par le relais.
3. Évasion du conteneur ou abus d'une image compromise.
4. Exfiltration par réseau, logs, erreurs ou dépendances.
5. Escalade progressive : une suite de petites actions autorisées produit un effet dangereux.
6. Empoisonnement des benchmarks pour faire accepter une « amélioration » trompeuse.
7. Consommation incontrôlée de GPU, disque, tokens ou temps.

## Contrôles minimaux

- deny-by-default ;
- signatures, expiration courte et base transactionnelle persistante d’empreintes HMAC de nonces ;
- images de sandbox épinglées par digest ;
- réseau désactivé par défaut ;
- aucun montage du home, du socket Docker ou des secrets ;
- aucun montage en écriture du workspace source : snapshot temporaire borné par tâche ;
- rejet des liens symboliques et fichiers spéciaux dans les snapshots ;
- suppression garantie du conteneur et du snapshot après succès, erreur ou timeout ;
- approbation locale, expirante et à usage unique pour écriture, réseau, installation, Git push et contrôle GUI ;
- limites CPU/RAM/PIDs/durée/sortie ;
- jeux de tests protégés en lecture seule ;
- bouton d'arrêt local et révocation immédiate des sessions ;
- journal d’audit minimal : aucune charge utile brute, empreintes HMAC à domaines séparés et chaîne vérifiée avant chaque ajout ;
- clé d’audit distincte du secret d’authentification ;
- base d’approbation transactionnelle : aucune charge utile brute, liaison HMAC à la tâche et décision locale uniquement.

## Limites résiduelles

- le verrou du journal protège les threads du processus courant, pas plusieurs processus writers ;
- un attaquant qui compromet à la fois le processus et `SLG_AUDIT_KEY` peut fabriquer de futures entrées ;
- le dernier HMAC n’est pas encore ancré dans un stockage externe append-only ;
- une restauration ancienne ou une suppression de la base anti-rejeu peut oublier des nonces encore actifs ; un ancrage monotone externe reste à ajouter ;
- la base d’approbation et le journal d’audit ne forment pas une transaction atomique commune ; une panne entre les deux écritures peut demander une réconciliation locale.

## Actions exclues du MVP

- shell arbitraire sur l'hôte ;
- ouverture de ports publics ;
- persistance automatique ;
- accès aux navigateurs personnels ;
- récupération de secrets ;
- désactivation des protections de l'OS ;
- clics GUI sans confirmation et capture globale permanente.
