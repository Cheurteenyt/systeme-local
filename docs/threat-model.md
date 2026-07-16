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
- signatures, expiration courte et cache de nonces ;
- images de sandbox épinglées par digest ;
- réseau désactivé par défaut ;
- aucun montage du home, du socket Docker ou des secrets ;
- approbation pour écriture, réseau, installation, Git push et contrôle GUI ;
- limites CPU/RAM/PIDs/durée/sortie ;
- jeux de tests protégés en lecture seule ;
- bouton d'arrêt local et révocation immédiate des sessions ;
- logs signés et exportables.

## Actions exclues du MVP

- shell arbitraire sur l'hôte ;
- ouverture de ports publics ;
- persistance automatique ;
- accès aux navigateurs personnels ;
- récupération de secrets ;
- désactivation des protections de l'OS ;
- clics GUI sans confirmation et capture globale permanente.
