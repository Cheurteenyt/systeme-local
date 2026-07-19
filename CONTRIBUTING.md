# Contribuer à Système Local

Système Local manipule des frontières de confiance sensibles. Toute contribution doit privilégier
le refus par défaut, les capacités explicites, la traçabilité, l’isolation et la compatibilité des
contrats publics.

## Préparer l’environnement

Le dépôt utilise `uv.lock` comme résolution Python reproductible. La version de bootstrap est
épinglée dans `tools/requirements-bootstrap.txt`.

```bash
python -m venv .venv
. .venv/bin/activate  # Windows PowerShell : .venv\Scripts\Activate.ps1
python -m pip install -r tools/requirements-bootstrap.txt
uv sync --frozen --extra dev --python python
```

Docker ou Podman n’est requis que pour les tests et capacités utilisant le runtime conteneurisé.

## Validation locale

```bash
uv lock --check
uv run --frozen --extra dev ruff check .
uv run --frozen --extra dev python scripts/check_python_format.py --worktree
uv run --frozen --extra dev python scripts/check_python_typing.py --worktree
uv run --frozen --extra dev python scripts/check_markdown_links.py
uv run --frozen --extra dev python scripts/check_evidence_governance.py \
  --as-of 2026-07-18T20:00:00Z \
  --fail-within-days 0
uv run --frozen --extra dev python scripts/audit_python_dependencies.py
uv run --frozen --extra dev pytest
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Le contrôle de format utilise un **formatting ratchet**. Les 57 fichiers Python historiques
non conformes au moment de l’adoption sont listés dans
`governance/ruff-format-baseline.txt`. La baseline ne peut pas croître, et tout fichier Python
touché doit être formaté. Ce mécanisme permet de réduire la dette sans mélanger un reformatage
global avec un lot d’architecture ou de sécurité.

Le **Mypy ratchet** applique la même règle. Tous les scripts de gouvernance doivent être
entièrement typés. Trois diagnostics historiques dans deux fichiers de modèles provider sont
consignés dans `governance/mypy-baseline.json`; aucun nouveau diagnostic n’est permis, et toucher
un fichier concerné oblige à retirer sa dette au lieu de la reconduire.

L’audit des dépendances exporte `uv.lock` en requirements hashé avec le projet local exclu, puis
exécute `pip-audit` sans résolution `pip`. L’environnement éditable de développement n’est donc
ni la source de vérité ni une cause d’échec de collecte.

Le workflow planifié de gouvernance utilise l’heure réelle pour signaler les profils provider
proches de l’expiration. Les tests ordinaires utilisent une date explicite et restent
déterministes.

## Workflow Git

1. Créez une branche courte depuis le SHA courant de `main`.
2. Ajoutez ou mettez à jour les tests avec le changement.
3. Utilisez un commit ciblé et une PR draft.
4. Décrivez les permissions, effets de bord, données temporaires, preuves et risques.
5. Attendez tous les checks, puis utilisez le cleanup contrôlé du lot.

## Autorité documentaire

Consultez [`docs/documentation-governance.md`](docs/documentation-governance.md). Une modification
doit mettre à jour le document qui possède réellement la décision :

- blueprint pour la cible ;
- architecture pour l’implémentation actuelle ;
- connectivity model pour les règles cross-provider ;
- provider-neutral contract pour les invariants communs ;
- provider document pour les faits volatils ;
- threat model pour une nouvelle frontière ;
- ADR pour une décision structurante ;
- roadmap seulement après preuve de merge.

## Exigences de sécurité

- Aucun shell arbitraire exposé comme capacité publique.
- Aucun secret, cookie, jeton, identifiant provider privé ou preuve brute dans le dépôt.
- Toute entrée distante est non fiable et doit être validée.
- Toute action sensible est bornée par une politique et, si nécessaire, une approbation.
- Les accès fichiers, réseau, processus et périphériques sont explicitement déclarés.
- Une réponse de modèle ou attestation non vérifiée n’est jamais une autorisation.
- Les schémas publics et domaines de digest ne changent pas sans décision de compatibilité.
- Les dates de revalidation provider font partie de la sécurité.

Pour une vulnérabilité exploitable, suivez `SECURITY.md` et utilisez un canal privé.
