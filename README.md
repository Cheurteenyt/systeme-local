# Système Local Agent Gateway

Passerelle locale sécurisée permettant à un agent IA distant de demander des actions limitées sur un poste de travail, sans lui donner un accès direct au système hôte.

> **État : fondation expérimentale.** Le code actuel valide quelques invariants de sécurité. L'architecture produit universelle est décrite dans [`docs/blueprint-v2.md`](docs/blueprint-v2.md). Le contrôle graphique complet du poste, l'accès arbitraire au shell et l'exposition directe sur Internet sont volontairement exclus de cette fondation.

## Principes

- Connexion **sortante uniquement** depuis le poste local vers un relais ou un adaptateur.
- Capacités explicites plutôt qu'un shell libre.
- Exécution dans des conteneurs éphémères, sans réseau par défaut.
- Snapshot temporaire par tâche : le workspace source n’est jamais monté en écriture.
- Répertoire de travail dédié, jamais le disque complet.
- Quotas CPU, mémoire, durée et taille de sortie.
- Approbation humaine pour les actions sensibles.
- Journal d'audit append-only avec empreintes des entrées/sorties.
- Adaptateurs fournisseurs remplaçables : GLM/z.ai, API compatible OpenAI, MCP, GitHub, relais HTTPS.

## Portée du produit

Le projet vise une infrastructure générique de délégation sécurisée entre agents distants et ressources locales. L'amélioration d'un harness d'évaluation d'IA locales est un scénario de validation, pas la finalité du produit.

### Scénario de validation initial

Le premier scénario testable est l'amélioration d'un harness d'évaluation d'IA locales :

1. l'agent web envoie une tâche structurée ;
2. le gateway local lance les tests dans un conteneur isolé ;
3. les résultats volumineux restent en local ;
4. seuls les métriques, erreurs nouvelles et diffs utiles remontent ;
5. une modification n'est promue que si les seuils de qualité et de sécurité sont respectés.

## Démarrage

Prérequis principal : Python 3.11+. Docker ou Podman est recommandé et requis uniquement pour les capacités utilisant la sandbox conteneurisée.

```bash
python -m venv .venv
. .venv/bin/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -e '.[dev]'
cp .env.example .env
make sandbox-image
pytest
uvicorn systeme_local_gateway.main:app --host 127.0.0.1 --port 8765
```

Le service écoute uniquement sur `127.0.0.1`. Pour une communication distante, utilisez un relais authentifié avec un modèle **pull** : le poste local récupère les tâches, il n'accepte pas de connexion entrante publique.

## Exemple de tâche

```bash
python examples/sign_task.py > /tmp/task.json
curl -X POST http://127.0.0.1:8765/v1/tasks \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/task.json
```

## Capacités MVP

- `workspace.list`
- `workspace.read_text`
- `workspace.write_text`
- `sandbox.run_tests`
- `git.diff`

Les capacités sont définies dans `policy.yaml`. Pour les commandes sandboxées, le gateway copie les fichiers réguliers dans un snapshot borné, écarte certains fichiers secrets courants et les métadonnées Git sensibles, exécute la commande uniquement sur cette copie, rapporte les fichiers ajoutés/modifiés/supprimés, puis détruit le snapshot. L’image de sandbox est construite avec `make sandbox-image` et devra être épinglée par digest avant un usage de production. Toute capacité inconnue est refusée.

## Connectivité avec les IA web

Le projet distingue strictement trois modes :

- **MCP entrant** : l'utilisateur écrit dans l'interface web et l'agent web appelle le MCP ; aucune API modèle n'est requise par Système Local ;
- **API officielle sortante** : le Brain Router peut choisir et appeler automatiquement un fournisseur ;
- **handoff interactif** : une capsule signée est transférée par l'utilisateur lorsqu'une interface ne propose ni MCP ni API exploitable.

Une interface web privée n'est jamais traitée comme une API publique. Consultez le [`connectivity model`](docs/connectivity-model.md) pour le flux GLM prioritaire, le changement d'IA et la gestion des limites. Un exemple de registre est fourni dans [`providers.example.yaml`](providers.example.yaml).

## Architecture

Commencez par le [`blueprint v2`](docs/blueprint-v2.md), puis consultez le [`connectivity model`](docs/connectivity-model.md), [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md) et [`docs/roadmap.md`](docs/roadmap.md).

## Avertissement

Ce projet ne doit pas être utilisé comme RAT, outil furtif, mécanisme de contournement des restrictions d'un fournisseur d'IA, ni comme moyen d'obtenir une persistance non consentie. Chaque machine doit être administrée par son propriétaire, avec permissions explicites et bouton d'arrêt local.
