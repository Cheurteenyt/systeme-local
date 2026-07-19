## Résumé

Décrivez le problème traité, la solution retenue et la frontière qui reste explicitement hors
périmètre.

## Type de changement

- [ ] Protocole ou schéma public
- [ ] Sécurité / politique / modèle de menace
- [ ] Runtime / sandbox
- [ ] Adaptateur ou fournisseur
- [ ] Preuve officielle ou gouvernance d’expiration
- [ ] Correction
- [ ] Documentation / ADR / roadmap
- [ ] CI / dépendances / gouvernance GitHub

## Autorité documentaire

- [ ] Le document normatif propriétaire a été identifié.
- [ ] README, architecture implémentée, roadmap et provider docs restent cohérents.
- [ ] Une décision structurelle ajoute ou met à jour un ADR.
- [ ] Les faits provider volatils ont une date de revue et de revalidation.

## Sécurité et données

- [ ] Aucun secret, cookie, jeton, endpoint privé, chemin personnel ou preuve brute n’est ajouté.
- [ ] Les nouvelles permissions et capacités sont minimales et documentées.
- [ ] Les effets réseau, fichiers, processus et provider sont explicités.
- [ ] Le modèle de menace couvre la nouvelle frontière ou justifie l’absence d’impact.
- [ ] La rétention, destruction et récupération des données temporaires sont documentées.
- [ ] L’identité locale, le contexte provider et les sessions de transport restent séparés.

## Compatibilité

- [ ] Les schémas publics, imports publics et domaines de digest restent compatibles.
- [ ] Toute incompatibilité est une décision explicite, versionnée et testée.
- [ ] Le rollback ou la migration est décrit.

## Validation

- [ ] `uv lock --check`
- [ ] `ruff check .`
- [ ] formatting ratchet (`python scripts/check_python_format.py --worktree`)
- [ ] Mypy ratchet (`python scripts/check_python_typing.py --worktree`)
- [ ] tests Python complets et couverture
- [ ] audit des dépendances Python via lock exporté, hashé et sans projet local
- [ ] liens Markdown et contrats documentaires
- [ ] contrôle déterministe des dates de preuve
- [ ] `cargo fmt`, Clippy, tests, rustdoc et `cargo audit`
- [ ] tests Rust Windows lorsque la frontière Windows est concernée

## Risques et retour arrière

Décrivez les effets de sécurité, les états ambigus possibles, la procédure de révocation, le
rollback et les preuves permettant de confirmer le retour à un état sûr.
