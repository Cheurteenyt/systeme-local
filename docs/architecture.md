# Architecture

## Flux recommandé

```text
Agent web (GLM, autre LLM)
        |
        | tâche structurée, signée
        v
Relais minimal / adaptateur fournisseur
        ^
        | HTTPS sortant, mode pull
        |
Gateway local
  ├─ authentification + anti-rejeu
  ├─ moteur de politique
  ├─ file d'approbation humaine
  ├─ exécuteur de capacités
  ├─ sandbox Docker/Podman/VM
  └─ journal d'audit
        |
        v
Workspace dédié + harness IA local
```

## Séparation des responsabilités

### Agent web

Planifie, formule une intention et choisit une capacité. Il ne reçoit ni accès réseau direct au PC ni secret hôte.

### Adaptateur

Convertit les contraintes du fournisseur en enveloppes normalisées. Les adaptateurs sont remplaçables et ne possèdent jamais les primitives d'exécution.

### Gateway local

Source d'autorité. Il vérifie signature, expiration, nonce, identité, politique et quotas.

### Sandbox

Exécute une commande pré-approuvée avec réseau coupé, privilèges supprimés et workspace limité.

## Transports

1. **HTTPS pull** : choix par défaut. Le poste local interroge un relais ; aucun port domestique n'est exposé.
2. **MCP/Tool API** : pour les fournisseurs acceptant des outils personnalisés.
3. **GitHub transport** : utile pour des tâches de développement, mais seulement avec branches dédiées, signatures et protections.
4. **Mode manuel** : import/export d'une enveloppe JSON pour les environnements très restreints.

## Boucle d'amélioration du harness

- Conserver localement les transcriptions et artefacts volumineux.
- Calculer des métriques déterministes en local.
- Envoyer au superviseur web un rapport compact : changement de score, nouveaux échecs, diff et décision proposée.
- Faire générer plusieurs candidats, les tester en parallèle dans des sandboxes indépendantes.
- N'accepter une amélioration que si elle ne régresse pas les jeux de tests protégés.
