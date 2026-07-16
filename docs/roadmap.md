# Roadmap

La roadmap est désormais pilotée par l'architecture cible décrite dans [`blueprint-v2.md`](blueprint-v2.md). Le prototype Python actuel sert uniquement à valider les premiers invariants.

## Phase 0 — Contrat et conformité

- spécification Local Delegation Protocol v0.1 ;
- schémas de capacités, tâches, plans, décisions et reçus ;
- suite de conformité et vecteurs de test ;
- politique deny-by-default ;
- Ed25519, expiration, anti-rejeu et idempotence ;
- modèle de menace et ADRs publics.

## Phase 1 — Autorité locale

- daemon Rust minimal et multiplateforme ;
- registre de capacités versionnées ;
- moteur de politique et classes de risque ;
- état transactionnel des tâches ;
- approbations liées au hash du plan ;
- audit append-only chaîné par hash ;
- kill switch et révocation locale.

## Phase 2 — Exécution headless

- runtime WASI ;
- conteneurs durcis sans réseau ;
- workspace en overlay et snapshots ;
- Git, filesystem, tests et modèles locaux comme plugins séparés ;
- quotas CPU, RAM, GPU, disque, temps et sortie ;
- proxy d'egress contrôlé.

## Phase 3 — Interopérabilité

- adaptateur MCP Streamable HTTP ;
- adaptateur function calling GLM/OpenAI-compatible ;
- capsules signées pour les interfaces texte uniquement ;
- transport GitHub optionnel ;
- matrice de compatibilité par fournisseur et environnement ;
- edge et relais auto-hébergeables.

## Phase 4 — Délégation agent-à-agent

- endpoint A2A ;
- Agent Card et capacités authentifiées ;
- tâches longues, streaming, pause, reprise et annulation ;
- artefacts adressés par contenu ;
- reprise après crash et livraison durable.

## Phase 5 — Application de contrôle

- application desktop Tauri ;
- appairage, profils et permissions ;
- prévisualisation des plans et effets ;
- approbations, historique et rollback ;
- visualisation des données exportées ;
- gestion des nœuds et sessions.

## Phase 6 — GUI isolée

- microVM ou sandbox OS dédiée ;
- contrôle d'une application explicitement sélectionnée ;
- arbre d'accessibilité limité à la fenêtre ;
- vision seulement en fallback ;
- confirmation pour toute action externe ou irréversible ;
- captures expurgées et rétention courte.

## Phase 7 — Écosystème et durcissement

- SDK TypeScript et Python ;
- kit de plugins et registre signé ;
- SBOM, provenance et signatures de release ;
- fuzzing, tests d'évasion et chaos testing ;
- audit externe et bug bounty ;
- mode entreprise multi-tenant, SSO et SIEM.

## Gates obligatoires

Une phase ne peut pas promouvoir une capacité plus puissante sans :

- tests de conformité ;
- tests de politique ;
- tests d'isolation ;
- documentation des effets et du rollback ;
- métriques de fuite de données ;
- procédure de révocation ;
- revue du modèle de menace.
