# Assurance policy

The wallet provider decides the security values in the Key Attestation (KA)
itself, by applying a set of [SPOCP](https://github.com/sirosfoundation/go-spocp)
rules to evidence the backend verified. This replaces "trust the client's
claim if the batch looks trusted" with "grant what a rule says the verified
evidence supports".

The policy is **off by default**. When `enabled` is false the KA is produced
exactly as before, including the clamp to the software floor.

## What it decides

| KA claim | Decided by | Rule dimension |
| --- | --- | --- |
| `key_storage` | probing the configured levels, highest first | `assure-ks` |
| `user_authentication` | probing the configured levels, highest first | `assure-ua` |
| `certification` | probing the configured catalogue | `assure-cert` |

For `key_storage` and `user_authentication` the first permitted level wins.
The scheme's **floor** level is returned when nothing above it is permitted,
including with an empty ruleset: the policy fails closed to the floor and
never errors. An optional **ceiling** caps the result.

## Evidence

Evidence is one S-expression with a **fixed slot order** (schema version 1,
reported in the startup log, the audit line and the `policy_info` metric):

```
(evidence
  (verified
    (fido2 (mds3 trusted|none)(aaguid X)(uv present|none)(cert C))
    (platform (source S)(app_id A))
    (hsm (id I)))
  (claimed (plugin P)(key_storage T)(user_authentication T)(certification C)))
```

* `verified` holds only facts the backend verified itself: the per-key FIDO2
  record (`KeyAttestationRecord`, looked up by key thumbprint) and the wallet
  instance's `AttestationSource`. `claimed` is only ever filled from request
  fields and is never copied into `verified`.
* An absent verified slot is `(slot none)`, e.g. `(fido2 none)`. The builder
  always emits every slot.
* The `fido2` slot is `verified` only when **every** key in the batch has a
  FIDO2 record and all records agree on the AAGUID. Otherwise it is `none`.
* The instance's platform evidence is only used when the instance belongs to
  the authenticated caller: same tenant, and same user when the instance
  records one, the instance is active (suspended or revoked instances lend nothing), and
  its last WIA is within the effective WIA lifetime (`attestation.lifetime_seconds`
  capped by `wia.max_expiry_seconds`, as `signWIA` applies them; platform
  integrity is re-derived on every WIA, so older evidence is stale). A foreign `wallet_instance_id` is treated as unknown. This applies
  with the policy disabled too.
* `platform (source ...)` carries the stored string verbatim:
  `platform_attested`, `development_attested` or `backend_attested`. They are
  distinct atoms; `development_attested` is not treated as `platform_attested`.
* Not populated yet, always `none`: `uv` (the backend does not record user
  verification yet), `cert`, `app_id`, and the whole `hsm` slot.
* Evidence is built through the S-expression element API, never by string
  concatenation. Atom values are length-prefixed in the canonical encoding, so
  a hostile value such as `x)(source platform_attested` stays one atom.
  Empty or over-long (more than 256 bytes) values are replaced by `none`.
* `claimed.plugin` comes from the new optional `security_properties.plugin`
  request field. `claimed.key_storage` / `user_authentication` is the raw
  client string that maps to the highest level of that dimension's scheme.
  `claimed.certification` is the string, or `scheme/assurance_level` for an
  object.

## Rules

A rules file holds **one rule per line**, in go-spocp *advanced form*, each
preceded by a `# id: <name>` comment line. Ids appear in audit logs and are
unique. Blank lines and other `#`, `//` and `;` comment lines are ignored.

```
# id: prod-fido2-mds3-ks
(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid (* set AAGUID1 AAGUID2))))))
```

### The AAGUID set is the hardware filter (`fido2_hw`)

An authenticator counts as **hardware** (`fido2_hw`) only if the operator's
rules list its AAGUID: the documented premise is *MDS3 trusted* **and**
*operator-listed AAGUID*. The backend does not read MDS3 `keyProtection`, so
MDS3 trust alone never says "hardware". Therefore no `assure-ks` /
`assure-ua` rule that grants a tier above the scheme floor from verified
`fido2` evidence may omit an `(aaguid (* set ...))` constraint. The linter
warns on such a rule (see Linting) and the shipped templates are tested to
have no such finding.

Follow-up (not started): expose MDS3 `keyProtection` from go-trust so
`fido2_hw` does not rest on the AAGUID list alone.

Queries have the form `(assure-ks (tier T)(evidence ...))`,
`(assure-ua (tier T)(evidence ...))` and `(assure-cert (name N)(evidence ...))`.
A rule grants a tier by naming it; `(tier (* set a b))` lists every tier it
allows. There is no implicit "at or below" and **no negation**: deny is the
absence of a rule.

### Matching semantics the engine gives you

These are pinned by `internal/assurance/spocp_semantics_test.go` against
go-spocp v0.1.0:

* A query matches a rule when the top-level tag is equal and each query
  element matches the rule element at the **same position**. Extra trailing
  elements in the query are fine. Lists are positional, which is why the slot
  order is fixed.
* A rule lists a **prefix** of the slots. Use the bare empty list as
  "don't care": `(platform)` matches any platform slot but still requires it
  to exist. `(verified)` means any verified group. Skipping or reordering a
  slot (for example writing only `(claimed ...)` without `(verified)` before
  it) makes the rule silently dead; the linter reports it as an error.
* Star forms (`(* set ...)`, `(* prefix ...)`) work in rules because the file
  is loaded in advanced form. A wildcard or `*` atom in a *query* never
  matches a concrete value.
* The engine is indexed by the top-level tag.

### File rules

* The file name must **not** end in `.spocp` or `.bin` (go-spocp loads those as
  binary). Use `.rules`. Both the config validation and the loader reject them.
* An existing but empty rules file is valid: every dimension resolves to its
  floor. A missing file, or no `rules_file` while enabled, is a startup error.
* The loader refuses lines that go-spocp would misread: unbalanced
  parentheses (go-spocp otherwise drops the last character of the last atom),
  more than one expression on a line, and double quotes. It also refuses
  `(* range ...)` (go-spocp drops a dangling operator and builds an unbounded
  range that matches every atom) and an empty `(* set)`. Use `(* set ...)`,
  `(* prefix ...)` or `(* suffix ...)`.
* A commented-out example rule must not begin with `# id:`, or the id would be
  taken to belong to the next rule.
* The policy version is the sha256 of the file bytes.

## Configuration

`wallet_provider.attestation.assurance` (environment prefix
`WALLET_WALLET_PROVIDER_ATTESTATION_ASSURANCE_`):

| YAML key | Environment suffix | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | `ENABLED` | `false` | Switch the policy on. |
| `rules_file` | `RULES_FILE` | none | Path to the rules file. Required when enabled. |
| `level_schemes` | `LEVEL_SCHEMES` (JSON array) | built-in `iso_18045` | Named schemes: `id`, `levels` (weakest first), `values` (emitted strings, one per level), `floor`, optional `ceiling`. |
| `key_storage_scheme` | `KEY_STORAGE_SCHEME` | `iso_18045` | Scheme used for `key_storage`. |
| `user_authentication_scheme` | `USER_AUTHENTICATION_SCHEME` | `iso_18045` | Scheme used for `user_authentication`. |
| `lower_by_claims_key_storage` | `LOWER_BY_CLAIMS_KEY_STORAGE` | `true` | See below. |
| `lower_by_claims_user_authentication` | `LOWER_BY_CLAIMS_USER_AUTHENTICATION` | `true` | See below. |
| `certification.scheme` | `CERTIFICATION_SCHEME` | none | Default scheme for derived entries. |
| `certification.levels` | `CERTIFICATION_LEVELS` | none | With no `entries`, one entry per level (strongest first), named after the level. |
| `certification.entries` | `CERTIFICATION_ENTRIES` (JSON array) | none | Named entries: `name`, `scheme`, `assurance_level`, optional `url`. Probed in order; list the strongest first. |
| `certification_basis_in_claim` | `CERTIFICATION_BASIS_IN_CLAIM` | `false` | See "Certification basis". |

The built-in `iso_18045` scheme has the levels `basic`, `enhanced-basic`,
`moderate`, `high` (ISO 18045 order: VAN.2, VAN.3, VAN.4, VAN.5), emitting
`iso_18045_basic`, `iso_18045_enhanced-basic`, `iso_18045_moderate`,
`iso_18045_high`, with floor `basic`. Rules name **levels**, not emitted
strings. Other schemes are allowed; their emitted values are linted as a
warning when not registered by OpenID4VCI Appendix D.2.

`Validate()` is fail-closed: a bad scheme (unknown floor, duplicate level,
values not matching levels, ceiling below floor, names that are not plain
tokens), an unknown scheme reference, a bad certification entry or a bad
rules file name is a configuration error. A disabled policy is never
inspected.

### lower_by_claims

When true (default) and the client sent a claim for that dimension, the result
is `min(claimed level, granted level)`, never below the floor. A client can
therefore only ever lower its own result. With no claim nothing is lowered.
Claims are normalised first: for `iso_18045` the legacy SIROS vocabulary
(`software`, `hardware`, `trusted_execution`, `remote_hsm`) maps as it does
without the policy. An unrecognised claim counts as the floor. With several
claimed values the highest counts.

When false, the rules are the sole authority and claims matter only through
`(claimed ...)` groups in rules.

### key_storage_status

The status list index is derived from the chosen level's position in its
scheme: the floor (or below) is the basic index, the scheme's top level the
high index and anything between the moderate index. For `iso_18045` this is
exactly the grouping used without the policy. Other schemes are mapped by
level position.

## Linting

`assurance-lint -rules <file>` (or `-config <backend config>` to use its
schemes and catalogue) prints findings and exits 1 on any error. The same
checks run at startup; lint errors refuse to start, warnings are logged.

* **ERROR** a rule that is not a list, an unknown dimension tag, a slot order
  that is not canonical (the rule could never match), a missing or duplicate
  id, an unloadable line.
* **WARN** a rule whose `(claimed ...)` group has children (naming the rule
  id), a tier or certification name outside the configured scheme or
  catalogue, an open grant (`*`, prefix, range), an emitted value that is not
  a registered OpenID4VCI key storage / user authentication value.
* **WARN** an `assure-ks` / `assure-ua` rule whose verified `fido2` slot
  grants a tier above the configured scheme's floor, or constrains `mds3`,
  `uv` or `cert`, without an `(aaguid ...)` constraint (naming the rule id).
  A bare `(fido2)` is fine only when the rule grants nothing above the floor.
  An `(aaguid ...)` that accepts every model (`(*)`, or a set containing it)
  is no constraint, and an empty `(tier)` counts as granting every tier.
  The floor and level order come from the configured scheme, never from level
  names. Narrow the rule with `(fido2 (mds3 trusted)(aaguid (* set ...)))`.

## Observability

* Startup log `assurance policy loaded`: rules file, rule count, evidence
  schema version, policy hash.
* Metric `wallet_backend_assurance_policy_info{rules_file,schema_version,policy_hash}`
  (always 1) and counter `wallet_backend_assurance_decisions_total{dimension,level}`.
* Audit line `key attestation assurance decision` per KA: rule ids, policy
  hash, schema version, granted / claimed / chosen values. It never contains
  the nonce.

## Certification basis

An optional `basis` member (`{policy: <first 8 hex of the policy hash>, rules:
[ids]}`) inside the `certification` claim is implemented behind
`certification_basis_in_claim` and is **off and not spec-supported**.

* TS-03 v1.5.2 replaced `storage_certification_information` with "the
  `certification` field defined in Appendix D of OID4VCI".
* OpenID4VCI 1.0 and the 1.1 draft, Appendix D, define it as: "`certification`:
  OPTIONAL. A String that contains a URL that links to the certification of the
  key storage component." A string, not an object, so a `basis` member has no
  place in a conformant claim.
* WE BUILD CS-04 Annex C (wp4-architecture PR 229, informative) shows an object
  `{"scheme": ..., "assurance_level": ...}` and the string `"none"`. That is
  already beyond Appendix D, and Annex C says nothing about extra members.

Entries can therefore carry a `url`, which makes the emitted claim the URL
string Appendix D defines. Without a `url` the `{scheme, assurance_level}`
object of Annex C is emitted. Rule ids and the policy hash are always in the
audit line, which is where the basis belongs until a spec allows it. When
nothing is permitted the claim is `"none"` (Annex C).

## Shipped examples

* `deploy/assurance/production.rules.example`: verified-evidence rules only,
  with placeholder AAGUIDs (the AAGUID set is the hardware filter, see
  above; a test lints every shipped template for it). The user-authentication rule is commented out
  because it needs `(uv present)`, which is not recorded yet; platform rules
  belong to a later change.
* `deploy/assurance/gdc-simulation.rules.example`: grants every tier to a
  client that claims the `soft` plugin. Simulation only; it relies on
  client-claimed evidence on purpose. It only shows its effect with
  `lower_by_claims_*: false`, or when the client also claims the target level.

## Deployment

The backend needs two things: the configuration, and the rules file present at
`rules_file` inside the container.

```yaml
wallet_provider:
  attestation:
    assurance:
      enabled: true
      rules_file: /etc/wallet/assurance/assurance.rules
```

or `WALLET_WALLET_PROVIDER_ATTESTATION_ASSURANCE_ENABLED=true` and
`WALLET_WALLET_PROVIDER_ATTESTATION_ASSURANCE_RULES_FILE=/etc/wallet/assurance/assurance.rules`.

Mounting requirements for any orchestrator:

* the file must be readable by the backend user at the configured path, and
  its name must end in `.rules` (never `.spocp` or `.bin`);
* mount it read-only; a ConfigMap is fine, or a Secret if the AAGUID
  allow-list is considered sensitive;
* the file is read once at startup, so a change needs a restart (the policy
  hash in the startup log and the `policy_info` metric shows which version is
  live);
* the backend refuses to start if the file is missing or fails lint.

The sirosid-dev Helm chart does **not** support this yet. Its ConfigMap and
volume mount for the rules file are pending; until they exist, the file has
to be provided by other means.
