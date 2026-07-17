# Blueprint v2 — Système Local

## 1. Vision

Système Local est une infrastructure open source permettant à un agent IA distant, quel que soit son fournisseur, de déléguer des tâches à une machine locale sans obtenir un accès direct ou implicite au système hôte.

Le produit n'est pas un outil de prise de contrôle à distance. C'est une **fabrique d'exécution gouvernée** : chaque action est décrite, validée, autorisée, isolée, observée et vérifiée avant que ses effets ne soient conservés.

### Publics visés

- développeurs utilisant du calcul, des dépôts ou des modèles locaux ;
- chercheurs exécutant des expériences reproductibles ;
- utilisateurs souhaitant conserver leurs données en local ;
- équipes utilisant des agents cloud avec des ressources on-premise ;
- entreprises ayant besoin de contrôle, d'audit et de séparation des responsabilités ;
- créateurs souhaitant automatiser des applications sans exposer leur poste personnel.

## 2. Principe fondateur

> L'agent distant propose une intention. Le nœud local reste la seule autorité capable d'autoriser et d'exécuter ses effets.

Aucun protocole externe, aucun fournisseur de modèle et aucun relais réseau ne devient une frontière de confiance.

## 3. Décisions structurantes

### 3.1 MCP est une façade, pas le noyau

MCP est utilisé pour exposer des outils et des ressources aux hôtes qui le prennent en charge. Un appel MCP est toujours converti en tâche interne et traverse le moteur de politique, le moteur de risque, les approbations et le runtime isolé.

Le projet ne fournit jamais de primitives MCP génériques telles que `execute_command`, `read_any_file` ou `control_desktop`.

### 3.2 A2A est l'interface de délégation agent-à-agent

A2A est utilisé pour les tâches longues, asynchrones, annulables, multi-tours et produisant plusieurs artefacts. Le nœud local peut être découvert comme un agent spécialisé sans exposer son implémentation interne.

### 3.3 Le protocole interne est indépendant

Le **Local Delegation Protocol (LDP)** est le contrat interne canonique. MCP, A2A, le function calling, GitHub ou les capsules manuelles ne sont que des adaptateurs vers LDP.

Cette séparation empêche le produit de dépendre des limites d'un fournisseur ou d'une version de protocole.

### 3.4 Le réseau est sortant par défaut

Le poste local établit lui-même une connexion vers un relais ou un endpoint approuvé. Aucun port entrant n'est ouvert automatiquement sur le réseau domestique ou professionnel.

### 3.5 Les transports de modèles sont séparés

Le produit distingue un agent web qui **appelle le MCP** d'un fournisseur que le nœud peut **appeler par un contrat machine documenté**. Le premier est un client entrant et ne peut pas être sélectionné automatiquement comme s'il s'agissait d'un fournisseur sortant. Le second passe par un adaptateur propre au fournisseur. Les interfaces sans contrat fiable utilisent un handoff interactif signé ou restent en phase de caractérisation.

Chaque fournisseur web possède un profil de capacités explicite. ChatGPT est le premier fournisseur caractérisé ; ses surfaces MCP, API et conversation web visible ne sont jamais supposées équivalentes.

Les règles communes sont spécifiées dans [`connectivity-model.md`](connectivity-model.md) et le profil ChatGPT dans [`providers/chatgpt.md`](providers/chatgpt.md).

### 3.6 Les actions sont transactionnelles

Toute action significative suit le cycle :

`intention -> plan immuable -> simulation -> décision de politique -> approbation éventuelle -> exécution -> vérification -> commit ou rollback`

L'approbation est liée cryptographiquement au hash du plan. Une modification des paramètres invalide l'approbation.

## 4. Architecture cible

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Agents distants                                                    │
│ GLM / OpenAI / Claude / IDE / agent A2A / interface web fermée     │
└───────────────┬─────────────────────────────────────────────────────┘
                │
        MCP · A2A · Function Calling · GitHub · Capsule manuelle
                │
┌───────────────▼─────────────────────────────────────────────────────┐
│ Edge adapters                                                      │
│ - traduction vers LDP                                              │
│ - authentification externe                                         │
│ - filtrage des outils visibles                                     │
│ - streaming et reprise                                             │
└───────────────┬─────────────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────────────┐
│ Relais optionnel                                                    │
│ - rendez-vous et livraison                                         │
│ - file durable                                                     │
│ - présence des nœuds                                               │
│ - aucune capacité d'exécution                                      │
└───────────────┬─────────────────────────────────────────────────────┘
                │ connexion sortante, sessions courtes, révocables
┌───────────────▼─────────────────────────────────────────────────────┐
│ Local Control Plane                                                │
│ Identity · Capability Registry · Policy · Risk · Approval          │
│ Task State Machine · Budgets · Audit · Artifact Metadata           │
└───────────────┬─────────────────────────────────────────────────────┘
                │ plan autorisé
┌───────────────▼─────────────────────────────────────────────────────┐
│ Execution Plane                                                    │
│ WASI · conteneur · gVisor/Kata · microVM · helper hôte contraint   │
└───────────────┬─────────────────────────────────────────────────────┘
                │
┌───────────────▼─────────────────────────────────────────────────────┐
│ Ressources locales                                                 │
│ workspaces · Git · modèles · GPU · navigateurs isolés · apps VM    │
└─────────────────────────────────────────────────────────────────────┘
```

## 5. Compatibilité universelle par niveaux

Une intégration automatique avec toute interface web fermée est impossible si celle-ci ne fournit aucun outil, aucune API et aucun accès réseau. Le produit garantit donc une dégradation progressive.

| Niveau | Capacité de l'agent distant | Adaptateur |
|---|---|---|
| 0 | Texte uniquement | capsule signée copier/coller |
| 1 | Lecture/écriture GitHub | issues, branches et PR dédiées |
| 2 | Function calling ou API compatible OpenAI | adaptateur de fonctions |
| 3 | Client MCP distant | serveur MCP edge |
| 4 | Client A2A | endpoint agent-à-agent |
| 5 | SDK natif | LDP direct |

GLM est prioritaire via deux chemins : function calling compatible OpenAI et MCP lorsqu'il est disponible dans l'environnement utilisé.

## 6. Local Delegation Protocol

### 6.1 Objets principaux

- `Principal` : utilisateur, organisation, agent, session et appareil ;
- `CapabilityManifest` : actions exposées, schémas, effets et risques ;
- `TaskRequest` : objectif, contraintes, budgets et références d'artefacts ;
- `ExecutionPlan` : liste immuable d'étapes et de ressources ;
- `PolicyDecision` : allow, deny ou require_approval avec justification ;
- `ApprovalGrant` : autorisation courte liée au plan et au principal ;
- `TaskEvent` : progression ordonnée et rejouable ;
- `ArtifactRef` : contenu adressé par hash ;
- `ExecutionReceipt` : preuve des entrées, politiques, runtime et sorties ;
- `CommitDecision` : conservation ou annulation des effets.

### 6.2 États d'une tâche

```text
submitted
  -> validating
  -> planning
  -> awaiting_approval | queued
  -> running
  -> verifying
  -> succeeded | failed | cancelled
  -> committed | rolled_back
```

Chaque transition est idempotente, horodatée, signée et associée à un identifiant de corrélation.

### 6.3 Représentation

- JSON Schema pour les adaptateurs et l'écosystème ;
- Protobuf pour les communications internes à fort volume ;
- références de contenu par SHA-256 ou BLAKE3 ;
- contexte de trace OpenTelemetry ;
- numéros de version explicites et négociation de capacités.

## 7. Modèle de capacités

Une capacité décrit davantage qu'un nom de fonction.

```yaml
id: workspace.patch.apply
version: 1.0.0
input_schema: schemas/workspace-patch-apply.json
output_schema: schemas/workspace-patch-result.json
risk_class: R3
side_effects:
  filesystem: write
  network: none
  external: false
runtime:
  minimum_isolation: container
approval:
  default: required
constraints:
  roots: ["workspace://active"]
  max_changed_files: 20
  max_bytes: 1000000
rollback: snapshot
```

Les outils visibles sont générés dynamiquement selon l'identité, le workspace, le mode utilisateur et la politique. L'agent ne voit pas les capacités auxquelles il ne peut pas prétendre.

## 8. Classes de risque

| Classe | Exemple | Politique par défaut |
|---|---|---|
| R0 | métriques et état public | automatique |
| R1 | lecture d'un workspace explicitement partagé | automatique avec journalisation |
| R2 | calcul éphémère sans réseau | automatique avec quotas |
| R3 | modification réversible ou réseau limité | approbation ou règle explicite |
| R4 | envoi, publication, suppression, achat, push | approbation obligatoire |
| R5 | privilèges hôte, secrets globaux, sécurité OS | refus par défaut |

Les petites actions sont évaluées comme une chaîne : plusieurs opérations R1/R2 peuvent devenir R4 par composition.

## 9. Isolation

### Tier 0 — fonction pure

WASM/WASI, aucun système de fichiers implicite, aucun réseau et limites strictes.

### Tier 1 — conteneur

Workspace en overlay, utilisateur non privilégié, capacités Linux supprimées, seccomp, cgroups et réseau désactivé.

### Tier 2 — sandbox renforcée

gVisor ou Kata Containers pour le code tiers, les dépendances et les outils complexes.

### Tier 3 — microVM

Firecracker, KVM, Hyper-V, Windows Sandbox ou Virtualization.framework pour les tâches non fiables ou graphiques.

### Tier 4 — helper hôte

Petit processus natif, audité et fortement typé. Il n'accepte jamais de shell arbitraire. Chaque action hôte correspond à une capacité dédiée.

## 10. Contrôle graphique

Le contrôle du bureau n'est pas une primitive générale.

Ordre de préférence :

1. API applicative ;
2. protocole sémantique spécialisé : LSP, Playwright, CDP, API Office, etc. ;
3. arbre d'accessibilité limité à une fenêtre ;
4. vision et coordonnées en dernier recours.

Les sessions graphiques à risque s'exécutent dans une VM dédiée. Les captures sont limitées à la fenêtre autorisée, expurgées localement et supprimées selon une durée de rétention courte.

## 11. Identité et autorisation

- identité distincte pour l'utilisateur, l'agent, l'adaptateur, le nœud et le plugin ;
- appairage initial par passkey, QR ou code à usage unique ;
- OAuth/OIDC à l'extérieur, mTLS entre services contrôlés ;
- grants de capacité courts, limités à une ressource et un budget ;
- révocation immédiate et rotation de clés ;
- aucune clé longue durée transmise au modèle.

Le moteur de politique reçoit : principal, capacité, ressource, contexte, risque, provenance, budget et état de la tâche.

## 12. Données, secrets et réseau

- classification locale des données avant export ;
- résultats minimisés et résumés avant transmission ;
- coffre de secrets séparé du workspace ;
- credentials éphémères délivrés à un processus précis ;
- proxy d'egress avec domaines, méthodes et volumes autorisés ;
- résolution DNS contrôlée ;
- blocage des URLs et redirections non approuvées ;
- aucune donnée brute sensible dans les logs.

Le relais peut être aveugle au contenu LDP lorsque l'adaptateur et le nœud utilisent un chiffrement applicatif. Un endpoint MCP public termine toutefois nécessairement le protocole MCP ; il doit donc être considéré comme une composante de confiance ou être auto-hébergé.

## 13. Défense contre les prompt injections

Les sorties de fichiers, pages web, outils, modèles et plugins sont marquées comme données non fiables. Elles ne peuvent jamais modifier la politique, créer un grant ou augmenter un budget.

Mesures principales :

- séparation stricte données/contrôle ;
- provenance et taint tracking ;
- politique déterministe hors LLM ;
- validation de schémas ;
- plans figés avant approbation ;
- détection des changements d'intention ;
- vérification indépendante après exécution ;
- interdiction de propager automatiquement des instructions découvertes dans les données.

## 14. Plugins

Les plugins ne sont pas chargés comme bibliothèques natives dans le daemon principal.

- processus séparés avec protocole typé ;
- manifeste signé ;
- permissions déclarées ;
- version et digest immuables ;
- SBOM et provenance de build ;
- sandbox définie par le manifeste ;
- registre approuvé, avec possibilité d'auto-hébergement.

## 15. Audit et reproductibilité

Chaque tâche produit un reçu contenant au minimum :

- identités et versions ;
- hash de la demande et du plan ;
- décision de politique et approbation ;
- image/runtime par digest ;
- ressources et budgets consommés ;
- artefacts d'entrée et de sortie ;
- événements d'exécution ;
- résultat de vérification ;
- décision de commit ou rollback.

Le journal local est append-only et chaîné par hash. L'utilisateur peut exporter un bundle de preuve sans exposer les contenus privés.

## 16. Architecture du dépôt cible

```text
apps/
  desktop/                 # permissions, approbations, historique, kill switch
  cli/
services/
  edge/                    # endpoints MCP, A2A, function calling
  relay/                   # livraison et présence, optionnel
crates/
  local-daemon/            # autorité locale en Rust
  policy-engine/
  task-engine/
  capability-registry/
  audit-log/
  runtime-manager/
packages/
  protocol/                # schémas LDP et code généré
  sdk-typescript/
  sdk-python/
adapters/
  mcp/
  a2a/
  glm/
  openai-compatible/
  github/
  capsule/
runtimes/
  wasi/
  container/
  microvm/
plugins/
  filesystem/
  git/
  browser/
  local-models/
  evaluation/
docs/
  architecture/
  security/
  adr/
```

### Choix technologiques proposés

- Rust pour le daemon, les politiques et les composants de sécurité ;
- TypeScript pour l'edge et les adaptateurs web ;
- Python pour les SDK ML, harness et workers scientifiques ;
- Tauri pour l'application de contrôle locale ;
- PostgreSQL pour un control plane multi-utilisateur ;
- SQLite en mode local autonome ;
- stockage d'artefacts compatible S3 ou filesystem adressé par contenu.

## 17. Modes de déploiement

### Local autonome

Tout fonctionne sur une seule machine. Les tâches sont importées par capsule, CLI ou outil local.

### Pairing personnel

Un edge léger et un relais hébergé permettent à l'utilisateur de connecter ses agents web à un ou plusieurs postes.

### Auto-hébergé

Organisation, identité, relais, stockage et politiques déployés sur l'infrastructure du client.

### Entreprise

Multi-tenant, SSO, politiques centrales, attestations de machines, intégration SIEM et haute disponibilité.

## 18. Roadmap de qualité

### Fondation

- spécification LDP v0.1 ;
- daemon Rust minimal ;
- registre de capacités ;
- policy engine ;
- tâches transactionnelles ;
- audit et test de conformité.

### Interopérabilité

- profils de capacités par fournisseur et cycle de vie normalisé ;
- caractérisation ChatGPT en premier fournisseur ;
- adaptateur MCP entrant ;
- adaptateur fournisseur sortant par contrat documenté ;
- capsules manuelles ;
- matrice de compatibilité automatisée.

### Délégation durable

- endpoint A2A ;
- streaming, pause, reprise, annulation ;
- artefacts adressés par contenu ;
- reprise après crash.

### Isolation renforcée

- WASI et conteneurs durcis ;
- proxy d'egress ;
- microVM ;
- campagnes d'évasion et fuzzing.

### Expérience utilisateur

- application desktop ;
- visualisation du plan et des effets ;
- approbations par lot ;
- rollback et restauration ;
- profils de sécurité.

### Écosystème

- SDK et plugin kit ;
- registre signé ;
- suites de conformité ;
- documentation bilingue ;
- programmes de bug bounty et audit externe.

## 19. Non-objectifs

- contourner les restrictions d'un fournisseur d'IA ;
- fournir un RAT ou une persistance furtive ;
- exposer un shell hôte universel ;
- promettre une compatibilité automatique avec une interface fermée sans API ;
- déléguer la sécurité à un prompt système ;
- autoriser un modèle à modifier ses propres politiques ou journaux.

## 20. Critère de réussite

Le projet est réussi lorsqu'un agent distant peut accomplir une tâche utile sur une ressource locale, tandis qu'un observateur indépendant peut déterminer :

1. qui a demandé l'action ;
2. quelle capacité a été accordée ;
3. quelles données ont été lues ou exportées ;
4. dans quel environnement l'action a été exécutée ;
5. quels effets ont été produits ;
6. qui ou quelle règle les a autorisés ;
7. comment les annuler ou les reproduire.
