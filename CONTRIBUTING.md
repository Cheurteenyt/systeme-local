# Contribuer à Système Local

Système Local manipule des frontières de confiance sensibles. Toute contribution doit privilégier le refus par défaut, les capacités explicites, la traçabilité et l’isolation.

## Préparer l’environnement

```bash
python -m venv .venv
. .venv/bin/activate  # Windows PowerShell : .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
ruff check .
pytest
```

Docker ou Podman n’est requis que pour les tests et capacités utilisant le runtime conteneurisé.

## Workflow Git

1. Créez une branche courte depuis `main`, par exemple `feat/ldp-task-envelope`.
2. Ajoutez ou mettez à jour les tests avec le changement.
3. Utilisez des commits ciblés au format Conventional Commits.
4. Ouvrez une pull request et décrivez les permissions, effets de bord et risques.

## Exigences de sécurité

- Aucun shell arbitraire exposé comme capacité publique.
- Aucun secret, cookie, jeton ou identifiant dans le dépôt, les fixtures ou les logs.
- Toute entrée distante est non fiable et doit être validée.
- Toute action sensible doit être bornée par une politique et, si nécessaire, une approbation.
- Les accès fichiers, réseau, processus et périphériques doivent être explicitement déclarés.
- Une réponse de modèle n’est jamais une autorisation.

Pour une vulnérabilité exploitable, suivez `SECURITY.md` et utilisez un canal privé plutôt qu’une issue publique.
