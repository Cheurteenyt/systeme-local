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
- Approbation humaine locale, explicite et à usage unique pour les actions sensibles.
- Journal d'audit minimal, chaîné par HMAC, sans arguments ni sorties brutes.
- Protection anti-rejeu persistante et transactionnelle entre les redémarrages.
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
# Remplacez SLG_SHARED_SECRET et SLG_AUDIT_KEY par deux secrets aléatoires distincts.
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

Les capacités sont définies dans `policy.yaml`. Pour les commandes sandboxées, le gateway copie les fichiers réguliers dans un snapshot borné, écarte certains fichiers secrets courants et les métadonnées Git sensibles, exécute la commande uniquement sur cette copie, rapporte les fichiers ajoutés/modifiés/supprimés, puis détruit le snapshot. L’image locale est construite avec une image Python de base épinglée par digest et le runner utilise `--pull never`. Pour un déploiement distribué, l’image finale devra elle aussi être référencée par digest. Toute capacité inconnue est refusée.

### Test d’intégration Docker

Le test d’intégration construit l’image et exécute de vrais conteneurs. Il vérifie que le workspace source reste inchangé, que le réseau et le système de fichiers racine sont bloqués, que les sorties sont bornées et que les ressources sont nettoyées après timeout.

```bash
make docker-integration
```

Sous PowerShell :

```powershell
docker build --pull -f Dockerfile.sandbox -t systeme-local-sandbox:dev .
$env:SYSTEME_LOCAL_RUN_DOCKER_TESTS = "1"
$env:SYSTEME_LOCAL_SANDBOX_IMAGE = "systeme-local-sandbox:dev"
python -m pytest -m integration -q
Remove-Item Env:SYSTEME_LOCAL_RUN_DOCKER_TESTS
Remove-Item Env:SYSTEME_LOCAL_SANDBOX_IMAGE
```

### Intégrité du journal d’audit

`SLG_AUDIT_KEY` doit être un secret aléatoire distinct de `SLG_SHARED_SECRET`. Le journal ne conserve jamais les arguments, sorties, identifiants de session ou messages d’erreur bruts. Il enregistre seulement des métadonnées sûres et des empreintes HMAC à domaines séparés. Chaque entrée inclut également le HMAC de l’entrée précédente.

Générez deux valeurs indépendantes avec :

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Vérifiez la chaîne complète avec :

```bash
python -m systeme_local_gateway.audit
```

Le service refuse de démarrer ou d’ajouter une entrée lorsque le journal est tronqué, altéré, signé avec une autre clé ou utilise l’ancien format non chaîné. Avant la première utilisation de ce format, archivez un éventuel `audit.jsonl` historique sous un autre nom. La clé HMAC protège contre les modifications hors ligne tant qu’elle reste secrète ; l’ancrage externe du dernier HMAC reste une amélioration future.

### Protection anti-rejeu persistante

Le gateway conserve les empreintes HMAC des nonces dans `SLG_REPLAY_DB`, qui vaut par défaut `.systeme-local/replay.sqlite3`. Les nonces bruts ne sont jamais écrits. L’insertion est transactionnelle : deux processus qui reçoivent simultanément la même tâche ne peuvent pas tous les deux l’accepter.

Les entrées expirées sont supprimées avant chaque insertion. Lorsque `SLG_REPLAY_MAX_ENTRIES` est atteint avec des tâches encore valides, le gateway refuse les nouvelles tâches avec une erreur temporaire au lieu d’évincer une protection active. La base est vérifiée au démarrage et une corruption empêche le service de démarrer.

La base peut être supprimée uniquement lorsque le gateway est arrêté et qu’aucune tâche signée encore valide ne pourra être rejouée. Une restauration de sauvegarde ancienne peut oublier des nonces récents ; un compteur monotone externe reste une amélioration future.

### Approbations humaines locales

Les capacités marquées `require_approval` ne peuvent pas être exécutées directement par
l’agent. La première soumission crée une demande locale et renvoie un `approval_id` opaque.
La base par défaut est `.systeme-local/approvals.sqlite3` et ne conserve ni arguments,
ni contenu, ni identifiant de session bruts.

Conservez le JSON signé exact utilisé pour la première soumission. Consultez ensuite la file
locale, puis fournissez ce fichier à la commande d’approbation :

```bash
python -m systeme_local_gateway.approvals list
python -m systeme_local_gateway.approvals approve <approval_id> --task-file /tmp/task.json
# ou
python -m systeme_local_gateway.approvals deny <approval_id>
```

La commande `approve` vérifie la signature du fichier, confirme qu’il correspond exactement
à l’empreinte HMAC de la demande, affiche localement l’identité, la capacité et les arguments,
puis exige de saisir l’identifiant complet. L’option `--yes` est réservée aux tests locaux
contrôlés et ne doit pas être utilisée pour une approbation humaine ordinaire.

Après une approbation, l’agent doit soumettre une nouvelle enveloppe signée avec un nouveau
nonce, le même `task_id`, la même identité, la même capacité et les mêmes arguments, ainsi
que `approval_id`. Toute modification invalide l’approbation. Une approbation expire, ne peut
servir qu’une fois et sa consommation est transactionnelle entre plusieurs processus.

Pour l’exemple fourni, conservez `SLG_TASK_ID` entre les deux soumissions et définissez
`SLG_APPROVAL_ID` pour la seconde. `SLG_TASK_CAPABILITY` et
`SLG_TASK_ARGUMENTS_JSON` permettent de choisir l’action signée.

### Erreurs d’exécution distantes

Une exception interne d’exécution n’est jamais renvoyée telle quelle à l’agent distant.
La réponse contient seulement `task execution failed` et l’`audit_id` associé. Le message
interne est transmis uniquement au journal d’audit, qui n’en conserve pas le texte brut :
il enregistre une empreinte HMAC et des métadonnées de taille et de type.

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
