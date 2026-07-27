# Modèle de menace

Status: current through the B1.6 logical-disposition boundary

## Actifs à protéger

- fichiers personnels et professionnels ;
- secrets, clés API, cookies, jetons Git et futurs credentials provider ;
- intégrité du système hôte et des workspaces ;
- confidentialité des prompts, modèles, pièces jointes et preuves opérateur ;
- budget GPU/CPU, API, stockage et tokens ;
- dépôts Git et chaîne de publication ;
- identité locale canonique des agents, tâches, projets et conversations ;
- décisions de politique, approbations, journaux et profils de preuves officielles.

## Frontières de confiance

Aucune des surfaces suivantes n’est une autorité locale :

- modèle distant ou réponse de modèle ;
- relais, provider, client MCP ou session de transport ;
- navigateur, DOM, URL copiée, label d’app ou sidebar ;
- attestation opérateur non vérifiée ;
- export UI brut ;
- document OAuth/OIDC ou métadonnée distante ;
- tunnel, endpoint TLS ou scan d’outils non attesté ;
- résultat de CI après expiration des preuves officielles.

Le gateway local, la politique locale, les approbations, les stores transactionnels et les
vérificateurs déterministes restent les autorités.

## Menaces principales

1. Prompt injection contenue dans une page, un dépôt, une pièce jointe ou une sortie de modèle.
2. Tâche falsifiée, rejouée, expirée ou modifiée par un relais.
3. Évasion du conteneur ou abus d’une image compromise.
4. Exfiltration par réseau, logs, erreurs, artefacts, dépendances ou preuves temporaires.
5. Escalade progressive : une suite de petites actions autorisées produit un effet dangereux.
6. Empoisonnement de tests, benchmarks ou preuves pour faire accepter une fausse amélioration.
7. Consommation incontrôlée de GPU, disque, tokens, appels provider ou temps.
8. Confusion entre identité locale, compte provider, conversation visible et session MCP.
9. Preuve officielle périmée, contradictoire ou interprétée à un niveau de généralité incorrect.
10. Attestation opérateur mensongère, mal cadrée ou produite sur le mauvais compte/workspace.
11. Collecteur de preuves compromis, qui substitue une source, un digest ou un horodatage.
12. Export UI brut contenant cookies, tokens, identifiants privés ou données d’autres workspaces.
13. Métadonnées OAuth/OIDC malveillantes : issuer, discovery, endpoints ou scopes substitués.
14. Attestation tunnel/TLS forgée ou endpoint public différent de celui qui a été revu.
15. Dérive des outils ou permissions entre scan, action review, publication et usage.
16. Ambiguïté d’acceptation après un appel provider ou une action locale.
17. Rollback ou divergence des stores d’audit, de contexte, de replay ou d’approbation.
18. Compromission de la chaîne GitHub, d’une action CI ou d’un outil d’audit non épinglé.

## Contrôles minimaux implémentés

- deny-by-default ;
- signatures, expiration courte et base transactionnelle persistante d’empreintes HMAC de nonces ;
- outils MCP dérivés de la politique ;
- loopback, `Host`, `Origin`, taille, débit et concurrence bornés ;
- snapshots de workspace temporaires, liens symboliques et fichiers spéciaux refusés ;
- réseau de sandbox désactivé par défaut ;
- quotas CPU/RAM/PIDs/durée/sortie ;
- approbation locale expirante, exacte et à usage unique ;
- journal minimal HMAC-chaîné et verrou interprocessus ;
- ancrage externe optionnel et vérificateur Rust secret-free ;
- erreurs génériques vers les agents distants ;
- stores SQLite versionnés, transactionnels et vérifiés sémantiquement ;
- identités locales canoniques et mappings provider optionnels ;
- modèles stricts, immuables et `extra=forbid` pour les contrats provider sensibles ;
- digests SHA-256 à domaines séparés ;
- profils officiels avec dates de revue et de revalidation ;
- ambiguïtés officielles fail-closed ;
- snapshots d’outils et action reviews liés à des digests et comptes bornés ;
- aucune donnée brute de pièce jointe ou preuve opérateur dans les modèles publics.

## Cycle obligatoire des futures preuves brutes

Une future procédure de collecte doit appliquer l’ordre suivant :

```text
scope exact du compte/workspace
  -> création dans un emplacement temporaire dédié
  -> permissions locales minimales
  -> inspection de type et de taille
  -> sanitisation déterministe
  -> vérification que les secrets et valeurs interdites sont absents
  -> calcul du digest
  -> création d’une attestation ou d’un record typé
  -> destruction vérifiée ou rétention explicitement autorisée
  -> reçu local sans contenu brut
```

Règles :

- aucune preuve brute dans Git, les fixtures, SQLite provider, les logs ou les modèles Pydantic ;
- aucune valeur d’endpoint, métadonnée OAuth, définition d’outil ou capture UI dans le bundle public ;
- un digest ne prouve pas l’authenticité de la source sans une attestation compatible ;
- absence, contradiction, échec de sanitisation ou dépassement de durée produit `unknown` ou
  `failed`, jamais `verified` ;
- une panne avant destruction doit laisser un état récupérable et visible localement ;
- la rétention doit avoir une durée, un propriétaire, une justification et une procédure de
  suppression vérifiable.

## Contrôles requis avant une connexion ChatGPT MCP réelle

- revalidation des sources officielles ;
- preuve du plan, rôle, client et workspace exacts ;
- attestation de transport liée à l’endpoint réellement prévu ;
- issuer OAuth/OIDC allowlisté et métadonnées sanitizées ;
- secret storage séparé, rotation et révocation ;
- refresh-token capability vérifiée sans stocker sa valeur dans les modèles ;
- scan exact des outils, comparaison de drift et action review ;
- digest exact de la politique locale ;
- bundle complet encore valide dans sa fenêtre de quinze minutes ;
- approbation opérateur distincte pour chaque étape ayant un effet externe.

## Limites résiduelles

- le verrou interprocessus suppose un système de fichiers local fiable ;
- un attaquant qui compromet le processus et une clé HMAC peut fabriquer de futures entrées ;
- l’ancrage fichier ne résiste au rollback que sur un support séparé réellement append-only ;
- une restauration ancienne de la base anti-rejeu peut oublier des nonces actifs ;
- approbation et audit ne forment pas encore une transaction atomique commune ;
- un opérateur autorisé peut fournir une attestation fausse ; la provenance réduit mais
  n’élimine pas ce risque ;
- un digest sanitizé ne garantit pas que le document source était authentique ;
- les contrats provider peuvent changer avant la date planifiée de revalidation ;
- GitHub CI ne remplace pas une revue des permissions et paramètres effectifs du dépôt ;
- le package provider public reste large et doit être refactoré sans casser les imports ni les
  domaines de digest.

## Actions exclues

- shell arbitraire sur l’hôte ;
- ouverture automatique de ports publics ;
- persistance furtive ;
- accès aux navigateurs personnels ;
- récupération ou rejeu de secrets ;
- désactivation des protections de l’OS ou du provider ;
- clics GUI sans confirmation ;
- scraping de sidebar, DOM privé ou endpoints non documentés ;
- traitement d’une session MCP comme identité de conversation ;
- collecte réelle de preuves tant que son cycle de vie n’est pas implémenté et audité.

## Operator-evidence custodian boundary

Status: partial

### Assets at risk

Future raw operator evidence may contain paths, endpoint values, authentication metadata, tool
definitions, workspace facts or secret material.

### Process boundary

Python sends one versioned NDJSON request through stdin to a local Rust process. Rust emits one
secret-free and path-free response on stdout. The B0 wire protocol still permits only a synthetic
contract description and does not open evidence files.

### Controls implemented in B0

- exact protocol version and field allowlist;
- bounded input;
- one-request/one-response cardinality;
- strict identifier and lowercase SHA-256 syntax;
- no shell invocation or request data in CLI arguments;
- empty stderr required on success;
- typed fail-closed errors;
- Python recomputation of the private contract commitment;
- shared Python/Rust conformance fixtures;
- no filesystem, sanitizer or network capability in the synthetic descriptor.

### Controls implemented in B1.1

- opaque `ses_` identifiers with exactly 32 lowercase hexadecimal characters;
- one authoritative state/action transition graph;
- `disposed` terminal state;
- monotonic checked transition revisions;
- illegal edges and overflow preserve the prior session;
- deterministic private transition commitment with a separate digest domain;
- transition errors contain only the prior state and requested action;
- transition receipts contain no path, endpoint, secret, token, timestamp or raw evidence;
- the session module imports no filesystem, path, I/O or network capability.

### Controls implemented in B1.2

- exact opaque `src_` names with no path components;
- an open capability directory as the staging boundary;
- no-follow handling for the final source component;
- staging-root symlink and Windows reparse rejection;
- regular-file-only and single-hard-link requirements;
- reads authorized only in the `collecting` session state;
- fixed 16 KiB chunks and an 8 MiB absolute ceiling;
- checked arithmetic and rejection before appending beyond the selected limit;
- pre-open, handle and post-read identity/size/link/timestamp comparison;
- path-free typed errors;
- redacted `Debug`, no serialization and no public bytes getter;
- no staging reference from the B0 protocol or binary entrypoint;
- exact `cap-std` and `cap-fs-ext` dependency pins with lock and audit gates.

### Controls implemented in B1.3

- Rust creates one direct `stg_` child relative to an approved parent capability;
- creation is exclusive and rejects an existing child;
- Unix root and control-file modes are verified as `0700` and `0600`;
- Windows root and control-file DACLs are protected and owner-only;
- one `.custody.lock` file is acquired with create-new semantics;
- the lease binds the exact session, root identity and lock-file identity;
- controlled reads require the same live lease and the `collecting` state;
- dropping a lease removes only the control file and makes no disposition claim;
- protocol v1 and the binary entrypoint cannot invoke the controlled staging API.

### Residual risks and deferred controls

B1.3 proves controlled synthetic root creation, local access policy and exclusive lease
ownership. It does not yet prove operator-source provenance, resistance to every hostile same-file
mutation, sanitizer correctness, source/sanitized commitments, retention or disposition. Logical deletion
must not be described as physical erasure. B2 and B3 must add orchestration and operator-facing
non-disclosure tests before any real evidence is handled.

<!-- systeme-local:b1-4-source-commitment -->
## B1.4 source-commitment and profile threats

B1.4 addresses substitution and ambiguity between a controlled read and later sanitization. The
source commitment is domain-separated and binds session, byte length and every source byte. A
mismatched session, inactive or changed lease/root, unstable source, oversized source or
non-collecting state fails before a receipt is created.

The receipt is deliberately not a provenance or sanitization claim. The profile identifier space is
closed, limits are bounded by the 8 MiB custody ceiling, output is required to be deterministic and
network or secret-bearing environment input is forbidden. The profile registry does not authorize
provider access, readiness, retention or deletion.

<!-- systeme-local:b1-5-deterministic-sanitization -->
## B1.5 deterministic-sanitization threats and controls

B1.5 addresses parser ambiguity, profile confusion, source substitution and accidental disclosure of
sanitized bytes. The controlled entry point revalidates the live lease and exact source commitment
before transformation. Profile identifiers are closed, inputs and outputs are bounded, text
vocabularies are allowlisted, JSON fields are typed and duplicate/unknown fields fail closed.

The sanitized-output commitment binds the custody session, source commitment, profile identifier and
version, output class, output length and every sanitized byte under a dedicated private domain.
Receipts, errors and debug output omit paths, session identifiers, source names, endpoints, arbitrary
operator text and secret-bearing values.

Residual risks remain explicit: best-effort memory overwrite is not physical erasure; the receipt is
not proof of provenance or truth; retention and disposition are deferred to B1.6; and no real evidence
may enter this path before the B2/B3 orchestration and end-to-end non-disclosure gates.

<!-- systeme-local:b1-6-logical-disposition -->
## B1.6 retention and logical-disposition threats and controls

B1.6 addresses indefinite raw-source availability, artifact-retention ambiguity, partial cleanup and
false physical-erasure claims.

Controls include:

- raw staged sources are never retained after sealing;
- retention applies only to canonical sanitized artifacts;
- retention is closed to `local_operator` and at most 900 seconds;
- Rust reads no clock, environment, locale or network input;
- source, lease and root identities are revalidated before cleanup;
- unexpected children and linked or substituted objects fail closed;
- source, lease and root absence is verified in a monotonic retryable operation;
- sanitized bytes are explicitly overwritten before terminal disposition;
- late disposition remains mandatory and records `deadline_met=false`;
- receipts and errors omit paths, source names, session identifiers, timestamps, arbitrary text and
  secrets.

Residual risk remains explicit: memory overwrite and namespace absence do not erase SSD remanence,
filesystem journals, snapshots, swap, caches or backups. The receipt is a logical-disposition proof,
not a physical-erasure guarantee.


<!-- systeme-local:b2-0-orchestration-threats -->
## B2.0 protocol and orchestration design threats

B2.0 addresses path-authority expansion, Python raw-byte exposure, handle inheritance leakage,
process interruption, profile-to-check confusion and false promotion of incomplete evidence.

The selected controls are:

- an exact inherited-handle allowlist and no path in NDJSON, arguments or environment;
- one read-only regular source handle and one owner-only staging-parent handle;
- one-shot process transactions with hard Python timeouts;
- a bounded sibling recovery journal created before raw staging;
- `recover_evidence` cleanup that always emits `success_evidence_emitted=false`;
- wire-reachable `dispose_immediately` only;
- an exact eleven-check compatibility matrix;
- explicit gaps for UI readiness, OAuth summaries, transport attestations and high-risk tool counts;
- no reinterpretation of `destructive_count` as `high_risk_tool_count`;
- no reinterpretation of `app_state` or `access_control` as public request booleans;
- terminal disposition before a successful response;
- protocol-v1 and public-provider compatibility gates.

Residual risk remains: the future platform handle adapters and recovery journal are not implemented
in B2.0. Real evidence remains prohibited until B2.1, gap-profile review, B2.2 orchestration and B3
end-to-end non-disclosure gates are merged.


<!-- systeme-local:b2-0-contract-repair-v2 -->
## B2.0 independent-review closures

Revision 2 closes parser drift, projection substitution, unverifiable sanitized
commitments, journal rollback, over-broad inherited handles and stale evidence.

Controls include committed synthetic fixtures, exact reconstruction of all five
B1 outputs, per-check attestation domains, a hash-chained owner-only journal,
minimum-rights handle duplication, before/after identity verification, hard
timeouts and checked record/bundle expiry. None is described as implemented
runtime behavior.

## C0 Secure MCP Tunnel boundary

C0 introduces a temporary outbound control-plane connection while keeping the
MCP origin private on loopback. Threats include accidental public binding,
stolen runtime or bearer credentials, forwarded-header substitution, tool-scan
drift, replayed challenges, prompt-driven capability expansion, forged live
claims, raw-log leakage, and incomplete revocation.

Controls are a pinned official tunnel-client archive and SHA-256, process-local
secrets, exact loopback URLs, literal Host/Origin allowlists, independent bearer
authentication, disabled raw HTTP logging, a default-deny one-tool policy,
strict input/output schemas, process-local replay protection, fixed read-only
annotations, HMAC audit correlation, no B2 executor, no browser automation, and
a manual post-revocation failed call. Any unknown plan/role/permission,
metadata mismatch, non-loopback listener, OAuth requirement, missing audit, or
revocation failure blocks live attestation.

Residual risk is limited to the manually observed ChatGPT Web configuration and
the OpenAI control plane. C0 records only bounded states and digests; it cannot
cryptographically prove UI truth without the operator. The attestation expires
within 24 hours and never authorizes regular or write-capable use.

## C1 Chat-surface and attribution boundary

C1 adds threats from surface confusion, existing-chat overreach, hidden-model
inference, localized-label misattribution, cross-chat challenge replay, edited
manual receipts, and incomplete post-test revocation.

Controls are a pre-prompt enum-only surface observation, immutable
`work_tested=false`, two local test labels without provider conversation IDs,
separate runtime/default/Web-label models, domain-separated HMAC receipts,
strict extra-field rejection, one-tool policy/snapshot binding, distinct
challenge/response/audit requirements, bounded expiry, and a mandatory failed
post-revocation Chat call. Browser control requires fresh explicit operator
authorization and excludes sidebar/history access, private requests, cookies,
storage, unrelated tabs, developer tools, personal content, and API-key pages.

No official Plugin interface reviewed by C1 exposes account chat history or
conversation identifiers. The absence of that contract is a blocker, not
permission to scrape. Residual risk remains in manual truthfulness and visible
UI changes; signed receipts authenticate the recorded claims but do not turn
unsupported UI state into provider-issued evidence.

## C2 official-capability gate threats and controls

C2 addresses an earlier and narrower threat: performing sensitive setup for a
transport that the requested native Chat surface cannot officially use.

Threats include generic “ChatGPT” wording being mistaken for Chat, Tunnel
support being mistaken for surface support, stale documentation, source or
summary substitution, partial action enablement, provider-value confusion, and
bypass through C1 live scripts.

Controls are an exact provider/native-surface/capability tuple, a closed
three-state capability enum, official-host allowlisting, canonical summary and
profile SHA-256 commitments, sorted unique sources, synchronized
timezone-aware timestamps, a 14-day maximum freshness window, strict unknown
field rejection, and one atomic decision over Runtime key, Tunnel, Plugin, and
browser actions. The C1 preparation, facade, Tunnel, and operator-instruction
entry points call the C2 gate first.

C2 never opens Work, ChatGPT, history, existing chats, browser private state,
Security/Account settings, cookies, storage, private requests, or personal
content. It creates no credentials, listeners, tunnels, Plugins, prompts, or
tool calls.

Residual risk is official product documentation changing before the deadline.
Scheduled governance and fail-closed expiry bound but cannot eliminate that
risk. An officially supported profile would remain only a necessary
capability condition; live authorization and all C1 safety controls would
still be required.
