# Modèle de menace

Status: current through the sealed C8 boundary and the partial C9
attachment-handoff threat overlay

## Actifs à protéger

- fichiers personnels et professionnels ;
- secrets, clés API, cookies, jetons Git et futurs credentials provider ;
- intégrité du système hôte et des workspaces ;
- confidentialité des prompts, modèles, pièces jointes et preuves opérateur ;
- octets assainis temporaires, nonces synthétiques et exports de picker C9 ;
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
- résultat de CI après expiration des preuves officielles ;
- réponse d’une IA locale, même reçue depuis loopback ;
- apparence d’une pièce jointe dans Work ou Chat sans preuve des deux nonces.

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

## C3 evidence-lifecycle threats and controls

C3 addresses stale-evidence promotion, candidate self-authorization, active
profile replacement with recomputed digests, registry substitution,
cross-provider or cross-profile evidence reuse, official-domain lookalikes,
path traversal, time-boundary ambiguity, and partial enablement of a new
ChatGPT-side action.

Controls are separate canonical claim, conclusion, evidence-set, profile, and
registry SHA-256 commitments; exact reviewed-builder matching; a
registry-bound active-profile digest; strict HTTPS URL normalization; exact
provider-owned host allowlists; repository-contained profile paths; closed
provider, surface, capability, lifecycle, reviewer, and action enums; exact
warning/expiry boundaries; and atomic denial of Runtime-key, Tunnel, Plugin,
browser, and ChatGPT actions.

Candidate evidence is always non-authoritative. An unchanged candidate remains
blocked, while changed claims, sources, conclusion, or support become
`source_drift` and require independent review. Scheduled governance has
`contents: read`, creates no issue, and cannot mutate evidence.

C3 performs no browser, ChatGPT, Work, credential, Tunnel, Plugin, listener, or
MCP action. C3 remains the evidence authority while C4 owns current runtime
admission. Residual
risk is official documentation changing inside the bounded review window and
a human reviewer misclassifying a bounded claim. Expiry, independent review,
tests, and deliberate registry promotion limit but cannot eliminate those
risks.

## C4 runtime-admission threats and controls

C4 addresses direct-script and lower-level-import bypass, missing provider
context, provider/surface/profile/time substitution, admission-receipt
mutation or forgery, correlation replay/collision/capacity exhaustion,
policy-to-provider capability confusion, and tool-manifest privilege
expansion.

Controls are strict frozen request/decision models; canonical request and
receipt SHA-256 commitments; exact C3 decision/profile/evidence/registry
digests; exact production-adapter builder matching; closed action, reason,
lifecycle, reviewer, support, and access enums; exact identity matching; zero
tools on every denial; defensive model revalidation; reviewed-path and reparse
checks; a reduction-only MCP registry filter; per-tool protocol digests; a
bounded locked process-local correlation table; and one-time controller-issued
tool authority.

C1 protected entry points call C4 before state initialization, secret
generation, credential reads, environment mutation, listener creation,
`Start-Process`, or operator Plugin guidance. The historical C1 branch value
remains evidence, while current runtime use requires exact C4 branch and exact
reviewed C1 ancestry. Explicit provider mode repeats committed admission inside
Python before the MCP registry, audit/replay services, or listener can exist.

Residual risks are explicit. C4 is not an OS sandbox and cannot prevent manual
provider actions or independently launched out-of-repository processes.
Process-local replay state is not distributed replay protection. Generic
local MCP is not automatically a provider surface; a caller classifying it as
provider-bound must use explicit provider mode and the admitted constructor.
Scheduled C3 governance, separate live authorization, and future durable
replay storage remain necessary.

## C5 squash-integration threats and controls

C5 addresses evidence loss or ambiguity caused by squash-only history:
independent merging of stacked branches, deletion of a reviewed base branch,
commit substitution, reordered stack layers, tag substitution, diff-only
verification that misses modes, and tree-only verification that loses the
reviewed change boundary.

Controls are an exact frozen C0-C4 manifest; strict main base, PR, branch, and
head identities; pairwise ancestry verification; a SHA-256 binary-diff
commitment; an independent framed SHA-256 commitment over every tracked path,
mode, blob length, and blob byte; a one-file self-excluding final seal commit;
and an evidence tag that keeps the reviewed ancestry reachable after squash.

The covered, tagged, and accepted `main` trees must match the seal. The current
head must descend from the exact accepted C5 `main` commit. Unknown fields,
missing or moved tags, changed ancestry, mutations to any sealed tree,
manifest changes, or non-canonical paths fail closed. Later descendant changes
do not rewrite the historical C5 proof.

C5 does not protect against a repository administrator deleting every evidence
reference or rewriting the remote outside the reviewed workflow. It is not
code signing and does not replace independent review. The aggregate pull
request remains large, but this is an explicit consequence of preserving a
squash-only linear `main`. C5 performs no network, browser, provider, secret,
Tunnel, Plugin, listener, or ChatGPT action.

## C6 official-acquisition threats and controls

C6 addresses stale official evidence without allowing a remote documentation
service to become a capability authority. Threats include DNS or transport
failure, redirects, proxy or credential leakage, oversized responses,
malformed SSE/JSON-RPC, tool errors, multiple or substituted content blocks,
Unicode/whitespace ambiguity, harmless or semantic source drift, marker
spoofing, policy or C3 digest substitution, unsafe output paths, raw-content
retention, candidate auto-promotion, and scheduled-workflow privilege
expansion.

Controls are a fixed HTTPS endpoint and source-host allowlist; no redirects;
`trust_env=False`; no authorization or cookie; strict time and size bounds;
closed SSE/JSON-RPC/result schemas; NFC/newline/whitespace normalization;
exact reviewed byte counts and SHA-256 fingerprints plus bounded semantic
markers; strict frozen Pydantic contracts; canonical report digests; exact C3
registry/profile binding; reparse-aware repository inputs; atomic local output
restricted below `.systeme-local/c6`; and refusal when any transport/runtime
secret is configured.

Raw document bodies exist only in memory. An exact match may create only a
review candidate reproducing the current unsupported claims. Any drift creates
no candidate. Reports and candidates always state that they cannot change the
gate or promote evidence, and every outcome denies all six protected actions.
The scheduled workflow has only `contents: read` and uploads no candidate or
raw-content artifact.

Residual risks are compromise of every official source and reviewer at once,
documentation changes between scheduled runs, false-positive exact drift from
formatting, and human misclassification during a future deliberate promotion.
Short review windows, daily acquisition, multiple exact sources, independent
review, code review, successor sealing, and C4 runtime enforcement limit but
cannot eliminate those risks. C6 performs no ChatGPT, Plugin, Work, browser,
conversation, account, credential, Tunnel, listener, or provider-runtime
action.

## C7 Work-profile and pre-live authorization threats

C7 adds a supported Work profile without permitting Work activity.

| Threat | Control |
|---|---|
| Work evidence silently unblocks native Chat | exact literal Work identity; native Chat blocker and profile digest remain bound separately |
| an ordinary Chat request is upgraded to Work | `automatic_chat_to_work_switch_allowed=false` is immutable in policy and every decision |
| official support is mistaken for operator authorization | default decision denies all six effects and exposes zero tools |
| stale or drifted Work evidence authorizes a cycle | fourteen-day evidence window; due and expired states fail closed |
| a grant is replayed across profile, policy or surface | grant binds exact Work identity plus profile and policy SHA-256 values |
| a forged operator grant is accepted | process-local audit-key HMAC is mandatory; missing, short or wrong keys deny all actions |
| an old grant remains usable | maximum twenty-minute lifetime and strict `authorized_at <= now < expires_at` check |
| Work is unavailable or quota is stale | explicit Work request plus visible surface, available entitlement and usable quota observations no older than five minutes |
| browser scope expands during a live cycle | grant literals permanently deny existing chats, history operations, private browser state and account/security settings |
| tool scope expands | exactly one reviewed read-only probe and its C4 protocol digest are bound |
| prompt content requests files, commands, secrets or writes | those capabilities remain absent; grant literals cannot enable them |
| C7 accidentally performs the proposed C8 test | C7 has no grant creator or live script and refuses secrets, Tunnel processes and C0/C1 listeners |

C7 cannot prove a live Work invocation, current account entitlement, usable
quota, model routing or regular-use readiness. Those residual risks require a
separate C8 threat review and live evidence cycle.

## C8 bounded Work live-cycle threats

| Threat | Control |
|---|---|
| a broad assent is interpreted as Work authority | exact cycle-wide scope is committed and HMAC-authenticated; every excluded surface/capability is a literal false field |
| Work is selected implicitly from Chat | explicit visible Work selection is required; automatic switching and native Chat are immutable false |
| a different account/surface or stale quota is used | Work, entitlement and quota observations are visible, cycle-bound and no older than five minutes at grant/startup |
| the ignored grant file is substituted | exact cycle, profile, policy and observation digests plus HMAC; file must stay below `.systeme-local/c8` |
| provider mode bypasses admission | `main.py` revalidates committed C7/C8 governance and the live bundle before registry construction |
| a third or existing task is tested | exact labels A/B, maximum count two, separate fresh task receipts and no conversation identifiers |
| one call is replayed as two | unique challenges, responses, audit IDs and audit-record digests are required |
| prompt injection expands capability | registry contains one read-only probe; files, commands, secrets, writes, real evidence and protocol v2 do not exist in the surface |
| sensitive browser state is collected | browser queries remain bounded to the active Plugins and synthetic Work content; no cookies, storage, private requests, history navigation or existing-conversation content is collected |
| a visible label is promoted to internal model identity | only optional visible labels are stored; exact internal ID and regular-use claims remain false |
| live access survives the test | Tunnel/facade stop, listener check, Plugin removal, Runtime-key revocation, secret clearing and failed post-revocation call are all required |
| short-lived evidence expires before finalization | chronology proves calls occurred inside the grant; HMAC-bound historical receipts remain verifiable without extending authority |

Residual risks are a misleading visible product label, provider-side behavior
outside the observed two calls, compromised official pages and operator error
when revoking external credentials. Independent official sources, two-call
limits, one-tool local enforcement, short TTLs and explicit final revocation
reduce but do not eliminate those risks.

The executed C8 cycle exercised the replay, malformed-input, capability and
revocation controls without expanding the one-tool surface. The final
attestation commits two positive correlations, two failed replay audits,
schema rejection and post-revocation unreachability. Raw challenges,
responses, audit records, Plugin/Tunnel identifiers and credentials were
removed or left unversioned; the repository seal retains only typed counts and
irreversible commitments.

## C9 file, image and local-AI handoff threats

C9 adds a temporary raw-byte boundary that C8 did not have. Its live proof is
limited to one synthetic image and one synthetic UTF-8 document, one Work
task invoking one read-only MCP tool, and one normal Chat conversation
receiving the same package through a visible operator-performed file-picker
handoff. No C9 live action has yet occurred.

| Threat | Control |
|---|---|
| an arbitrary user file is substituted for the synthetic fixture | the live generator accepts no user paths; exact PNG-plus-TXT set, fixture commitments and independent random nonce hashes |
| traversal, symlink, reparse point or hard link escapes the selected object | absolute regular-file validation, safe component checks, link/reparse rejection, single-link requirement and fail-closed filesystem errors |
| a file changes between selection, local-AI inspection and delivery | opened-object fingerprint plus source/sanitized digest checks before and after every private callback; mutation terminates and cleans the lease |
| image metadata leaks location, device or unrelated context | C9 strips non-essential PNG and JPEG metadata and commits the sanitized bytes, never the source bytes, for delivery |
| malformed or compressed image exhausts resources | byte, dimension, pixel, decoded-byte, chunk and segment ceilings; bounded structural validation; unsupported type rejected |
| text carries invalid encoding, NULs or uncontrolled line structure | strict UTF-8 validation, normalization and byte/line ceilings |
| PDF or active document content reaches the first live transfer | the C9 live fixture is PNG plus `text/plain`; PDF, archives and generic binary inputs fail closed |
| attachment text or pixels prompt-inject the local AI | both inputs are explicitly delimited as untrusted data; the local model may return only the strict two-nonce JSON shape |
| a remote or DNS-rebound “local AI” receives bytes | endpoint requires exact host `127.0.0.1`, an explicit port and the exact path; hostnames, other loopback literals, user info, TLS URLs and non-loopback addresses are rejected |
| proxy, redirect or credential handling leaks local-AI traffic | proxy environment disabled, redirects disabled and authentication fixed to `none` |
| local-AI response smuggles extra content or false proof | response-size bound, duplicate-key and extra-field rejection, distinct nonce syntax and constant-time match against both expected hashes |
| a controlled HTTP response is reported as installed-runtime proof | final admission requires a separate fresh HMAC-bound runtime observation, inspected executable digest and endpoint/model commitments; the observation labels PID/process identity and privacy settings as operator-attested rather than automatically verified |
| adapter storage behavior is mistaken for runtime privacy | `adapter_persistent_storage_used=false` is scoped only to C9; runtime request logging and persistence are separate explicit operator confirmations |
| public models, logs or exceptions leak bytes, paths or nonces | public receipts are hash/size/time metadata only; raw output is private; safe generic errors; secret-free model validators |
| Work authority is counted as Chat authority | separate Work rich lease and Chat manual-export claim over equal package commitments; transport-specific receipt types |
| a successful or failed transfer is replayed | one-use Work lease, at-most-once picker claim, independent task/conversation identities and response nonce proofs |
| one transport is approved while the other is silently changed | one combined atomic approval binds the Work manifest, Chat manual manifest, exact authorities, local-AI receipt and cycle |
| a stale or forged approval/grant enables the tool | HMAC-bound evidence, strict maximum windows, digest revalidation, exact C8 ancestry and zero-tool default |
| the completed C8 grant is revived | C9 binds the immutable C8 evidence tag and records `c8_live_cycle_grant_reused=false`; it issues a fresh C9 grant |
| rich MCP rendering bypasses local policy or audit | executor returns metadata first; audit occurs before transport rendering; renderer receives only an approved delivery token and cannot replace mandatory metadata |
| a renderer returns excessive or malformed rich content | exact image/resource type validation, total response ceiling and generic failure without raw exception details |
| normal Chat is silently routed through Work or a private interface | the Chat leg permits only the public file picker; automatic switching, DOM heuristics, cookies and private endpoints are forbidden |
| a generic “new conversation” instruction is mistaken for Chat Plugin support | the explicit current rule “Plugins are not available in Chat” controls; Chat MCP exposure is denied |
| a successful Work call is counted as Chat | separate Work rich receipt and Chat manual-export/response receipt are mandatory |
| the manual Chat receipt is promoted to MCP/app/local-endpoint evidence | the typed Chat receipt denies all such claims; final attestation rejects their promotion |
| a visible app label is reported as an internal app ID | the Work receipt records only operator-visible selection plus endpoint/tool/cycle correlation and marks internal ID unverified |
| picker paths escape to a remote receipt | export metadata contains no path; paths are returned once only through the distinct authenticated loopback control plane |
| another ordinary local principal reads the Chat export | exact `0700`/`0600` POSIX modes; on Windows, inherited ACL removal plus an owner-only DACL query for the export root, handoff directory and files; permission failure denies materialization |
| a Chat export persists after use or crash | private state root, maximum ten-minute TTL, startup orphan cleanup, identity revalidation and cleanup on completion, cancellation, expiry and close |
| Chat export cleanup deletes an attacker-substituted target | root and file identity checks, link/hard-link drift detection and confined removal; unexpected objects fail closed |
| a third task/conversation expands scope | grant literals allow exactly one Work task and one normal Chat conversation; dynamic registry has at most one tool |
| provider prompt injection requests files, writes, commands, secrets or protocol v2 | those capabilities are absent from `policy.c9.yaml`, admission and the MCP registry |
| Runtime key or Work Plugin connection survives the proof | facade/Tunnel stop, listener checks, Work Plugin removal, operator key revocation, process-secret clearing and Work/control post-revocation unreachability are mandatory before final attestation |

Residual risks include:

- the runtime observation authenticates the recorded declaration and its
  bindings, but does not independently verify the operator-declared listening
  PID, product metadata or runtime privacy settings;
- an installed local model may behave differently outside the single bounded
  inference;
- ChatGPT may display or interpret a valid attachment differently from the
  observed nonce proof;
- operating-system ACL or deletion behavior cannot prove physical media
  erasure;
- the operating-system picker consumes path names, so a privileged local
  process can still race the last
  component-by-component and content-hash revalidation before selection;
- on Windows, private-state mutations use guarded path-based fallbacks where
  Python handle-relative operations are unavailable; component, identity and
  DACL checks narrow but do not eliminate a privileged check/use race;
- an owner-only DACL protects against ordinary principals, not an
  administrator, kernel compromise or offline disk access;
- provider-side copies may remain subject to the provider’s own retention
  rules after a successful transfer;
- an operator may select the wrong visible control or fail to revoke an
  external credential;
- the operator-visible Work app label is not an independently verified
  internal app identifier;
- an operating-system or process compromise can read in-memory bytes while
  the bounded cycle is active.

The exact-package scope, transport-specific nonce proofs, short TTLs, one-use
authority, minimal Work rich-content surface and explicit cleanup reduce
these risks but do not establish regular-use readiness. The manual path risks
must remain explicit even if the bounded Chat proof succeeds. See
[`providers/chatgpt-web-c9-attachment-handoff.md`](providers/chatgpt-web-c9-attachment-handoff.md).
