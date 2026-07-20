# Modèle de menace

Status: current through the B1.1 operator-evidence session lifecycle

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

### Residual risks and deferred controls

B1.2 and later B1 lots must define canonical path handling, file-type restrictions, bounded
streaming, temporary permissions, sanitizer allowlists, source/sanitized commitments and real
disposition receipts. Logical deletion must not be described as physical erasure. B2 and B3 must
add orchestration and operator-facing non-disclosure tests before any real evidence is handled.
