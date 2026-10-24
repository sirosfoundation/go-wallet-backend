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
| WIA S profile (`attestation_source`) | probing the configured profile list, highest first | `assure-wia` |
| whether a WIA is issued at all | yes/no | `assure-wia-issue` |
| WIA `wallet_solution_certification_information` | probing the configured catalogue | `assure-wia-cert` |

For `key_storage` and `user_authentication` the first permitted level wins.
The scheme's **floor** level is returned when nothing above it is permitted,
including with an empty ruleset: the policy fails closed to the floor and
never errors. An optional **ceiling** caps the result.

## Evidence

Evidence is one S-expression with a **fixed slot order** (schema version 2,
reported in the startup log, the audit line and the `policy_info` metric):

```
(evidence
  (verified
    (fido2 (mds3 trusted|none)(aaguid X)(uv present|none)(cert C))
    (platform (source S)(app_id A))
    (hsm (id I))
    (instance_key (kind K)(home H)(level L)(boot B)(binding attested|assertion)))
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
* `uv` is `present` when the authenticator reported user verification: the
  user-verified (UV) flag of the authenticator data of the FIDO2 attestation,
  recorded with the key's attestation record when the backend verified it.
  User presence (UP) is not user verification. With several keys in a batch
  `uv` is `present` only if EVERY record has it. Records stored before the
  flag was recorded read as `none`.
  The flag is only evidence when the attestation format's signature covers
  the authenticator data flags (`packed`, `android-key`, `tpm`, `apple`). In
  `fido-u2f` the signature does not cover them, so a u2f attestation always
  records `uv none` (anyone could set the bit on a valid attestation).
* `platform (app_id A)` is the application id the backend verified in the
  instance's most recent native attestation (`WalletInstance.VerifiedAppID`,
  set by the WIA path). The client-reported `DeviceInfo.AppID` is never used.
  Instances that last attested without native evidence have `app_id none`.
* Not populated yet, always `none`: `cert` and the whole `hsm` slot.
* `instance_key` (schema version 2, appended after `hsm` inside `verified`) is
  verified evidence about the wallet's **instance key** (the WIA PoP key): its
  `kind` (`fido2` today; `android_key`, `app_attest_assertion` in later
  stages), `home` (`strongbox`, `tee`, `secure_enclave_asserted`, `fido2_hw`,
  `hsm`), `level` (the security level the evidence reports), `boot` (verified
  boot state) and `binding` (`attested`: a chain or attestation object covers
  the key; `assertion`: an assertion ties the key to an attested device). Absent
  is `(instance_key none)`. It is filled only by the WIA path, only from the
  per-key evidence record looked up by the PoP key's thumbprint; key
  attestation leaves it `none`, and nothing in the `claimed` group can
  populate it. Fields the evidence does not report render `none`. Because
  rules match by position, `(kind)` must occupy position 1 when you constrain
  a later field, e.g. `(instance_key (kind)(home (* set strongbox tee)))`.

#### Schema version 2

The slot was **appended**, inside `verified` after `hsm`, and the schema
version went from 1 to 2. Rules written against version 1 keep matching: a
rule lists a prefix of the slots and a query may carry trailing elements, and
the `claimed` group still follows `verified` at the same position (pinned by
tests). A commented S1 template that
requires `instance_key (home (* set strongbox tee))` ships in
`deploy/assurance/production.rules.example`. It matches WIAs whose instance key
has verified `android_key` evidence (see "Android key attestation of the
instance key"), and stays commented: enable it only when your wallets submit
that evidence.
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

Queries have the form `(assure-ks (tier T)(evidence ...))`,
`(assure-ua (tier T)(evidence ...))`, `(assure-cert (name N)(evidence ...))`,
`(assure-wia (profile P)(evidence ...))`, `(assure-wia-cert (name N)(evidence ...))`
and `(assure-wia-issue (evidence ...))` (no candidate).
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
| `wia_profile_schemes` | `WIA_PROFILE_SCHEMES` (JSON array) | built-in `cs04_annex_c` | Named S-profile schemes: `id`, `profiles` (weakest first), `values` (emitted `attestation_source` strings, one per profile), `floor`, optional `ceiling`. |
| `wia_profile_scheme` | `WIA_PROFILE_SCHEME` | `cs04_annex_c` | Scheme the WIA profile is decided in. |
| `wia_certification.entries` | `WIA_CERTIFICATION_ENTRIES` (JSON array) | none | Named `wallet_solution_certification_information` values: `name`, `information` (object, emitted verbatim). Probed in order; list the strongest first. |

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

## Wallet Instance Attestation (WIA)

The same engine decides the WIA. With the policy disabled the WIA is produced
exactly as before: always issued, `attestation_source` is the verified source
verbatim.

### What a WIA request decides

* **`assure-wia-issue`**: is a WIA issued at all? When the policy is enabled
  and no rule permits the evidence, the request is refused with `403`
  `WIA_REFUSED_BY_POLICY` (no instance is recorded). Deny is the absence of a
  rule, so **a rules file without an `assure-wia-issue` rule refuses every
  WIA**; the linter warns about it, and the shipped examples contain a rule
  that permits everything, which is today's behaviour. An enabled policy that
  failed to load answers `503` `ASSURANCE_UNAVAILABLE`.
* **`assure-wia`**: the S profile, probed highest to lowest over the
  configured scheme; the scheme floor is returned when nothing above it is
  permitted, including with an empty ruleset. An optional ceiling caps it.
* **`assure-wia-cert`**: which `wallet_solution_certification_information`
  entry applies, probed over `wia_certification.entries`. When none is
  permitted the static `wallet_provider.wia.certification_info` is used, as
  without the policy.

### Evidence of a WIA request

Same schema and slot order as above (schema version unchanged).

* `platform (source S)(app_id A)` is what the backend verified in **this**
  request: `platform_attested` after a verified Apple App Attest / Play
  Integrity check, `development_attested` for an App Attest chain that only
  chained to a development environment, `backend_attested` when the request
  carried no native attestation (the baseline, which key attestation also sees
  as the stored source). It is never the instance's stored state from an
  earlier request.
* `fido2` is filled from the verified key-evidence record stored for the
  **instance key** (the thumbprint of the PoP key), when there is one and its
  kind is `fido2`; otherwise `none` (a WIA request itself carries no FIDO2
  evidence). This is KEY evidence about the instance key: K and S stay
  orthogonal, no shipped rule derives a credential key's KA level from it, and
  key attestation for credential keys only counts `fido2` records (never
  records of another kind). Caveat (ARKG): if the attested credential public
  key is not the PoP key (for example the PoP key is derived from it), the
  thumbprints differ, nothing matches and the result stays `none`.
* `claimed` is empty: a WIA request carries no client claims, so there is no
  lower-by-claims gate for the S dimension (the gates exist per dimension
  where a client claim exists: key storage and user authentication).

K and S are orthogonal (CS-04 Annex C.2.3): no shipped rule derives a key
storage level from the platform, or an S profile from a key.

### The S-profile scheme and where it is emitted

Findings from WE BUILD CS-04 Annex C (wp4-architecture PR 229, informative):

* The WIA tiers are **S1 full client attestation**, **S2 partial client
  attestation** and **S3 backend-only attestation** (C.2.2).
* Annex C defines **no** WIA claim for them: "TS-03 and CS-04 do not define a
  WIA claim that declares the attestation coverage level (S1/S2/S3)", and a
  wallet solution may signal it "via the certification information or via an
  extension claim" (C.3.2).

So the profile has no spec-registered home and no claim is added. The chosen
profile's emitted string goes into the claim the WIA already has for this,
the SIROS extension claim `attestation_source`. The built-in scheme
`cs04_annex_c` has the profiles `s3-backend-only` (emits `backend_attested`,
the floor) and `s1-full-client` (emits `platform_attested`), the strings the
WIA has always carried. S2 has no evidence source and no existing value, so it
is not in the default; a custom scheme can add it.

Consequences when the policy is enabled: `attestation_source` carries the
**profile's** value, so a `development_attested` request that no rule lifts to
S1 is emitted as `backend_attested` (a development attestation is not S1). The
verified source is not lost: it stays on the wallet instance record (which is
what key attestation uses as platform evidence), and the audit log and the WIA
issued audit event carry it as `verified_source`.
`wallet_solution_certification_information` is the spec-registered claim
Annex C names for per-tier references, and is the place `assure-wia-cert`
writes.

### Audit

Audit line `wia assurance decision` per WIA request: rule ids, policy hash,
schema version, issue decision, verified source, profile and its emitted
value, certification entry. The `WIA issued` audit event additionally carries
`verified_attestation_source`, `assurance_profile`, `assurance_policy_hash` and
`assurance_rule_ids` when the policy is enabled. Metrics:
`wallet_backend_assurance_decisions_total{dimension="wia_issue|wia_profile|wia_certification"}`.

### WSCD type

The wallet instance's `wscd_type` is `unknown` unless verified per-key evidence
says otherwise. The WIA PoP key is the wallet's **instance key in its own
keystore** (a software store or any WSCD plugin), not the App Attest / Play
Integrity attestation key. The WIA path looks the PoP key's thumbprint up in
the store of verified per-key evidence; when a record exists, `wscd_type` is
`wscdTypeFromKeyHome(record.home)` (see "Per-key evidence record" below), else
`unknown`. Nothing is derived from the platform attestation (`native_*` is not
guessed from App Attest / Play Integrity), from the client-reported plugin, or
as `web_crypto` (including for `development_attested`). Instances stored
earlier may still carry `web_crypto`, `native_*` or an empty type; they are
overwritten at their next attestation. A store error counts as no evidence.
An earlier version switched on the names `ios_app_attest` and
`android_play_integrity`, which no verifier stores.

`wscd_type` is never assurance evidence: the evidence schema has no slot for it
and no rule can read it (pinned by a test).

### Per-key evidence record (instance-key binding, stage B1)

Where the instance key lives can only come from evidence about **that key**.
`domain.KeyAttestationRecord` (per key, keyed by JWK thumbprint, never per
wallet instance) therefore carries, besides `aaguid`, `uv` and `verified_at`:
`kind` (`fido2`, later `android_key`, `app_attest_assertion`; records stored
before the field read as `fido2`), `home` (`strongbox`, `tee`,
`secure_enclave_asserted`, `fido2_hw`, `hsm`; old FIDO2 records read as
`fido2_hw`), and optional `security_level`, `verified_boot_state`,
`device_locked`, `patch_level`, `app_digest`, `chain_fingerprint`,
`chain_not_after`. Only verified evidence is ever stored, so a record's
existence means "verified".

`fido2_hw` means "an authenticator model the FIDO MDS3 registry trusts for this
attestation chain". That is the same premise the FIDO2 key-storage rules already
rest on: the trust decision is delegated to the PDP (ADR-010) and returns
trusted / not trusted, it does not report the metadata's `keyProtection`, so the
backend cannot tell a (rare) software authenticator model from a hardware one.
Operators who need hardware only pin the accepted AAGUIDs in their rules, as the
shipped examples do; making the home depend on `keyProtection` needs the PDP
decision to expose it first.

`wscdTypeFromKeyHome(home)` maps a verified record's home to a WSCD type
(`strongbox`/`tee` -> `native_android`, `fido2_hw` -> `fido2_hardware`,
`hsm` -> `remote`) and everything else, including `secure_enclave_asserted`, to
`unknown`. `secure_enclave_asserted` maps to `unknown` on purpose: an App
Attest assertion only proves that an attested app endorsed the key, not that
the key resides in the Secure Enclave, so it is never recorded as `native_ios`. It is never fed from the client-reported plugin or the
platform attestation.

**A record is never overwritten by weaker or absent evidence** (memory and
MongoDB stores; the MongoDB path is a compare-and-set on a revision). Homes
rank `secure_enclave_asserted` < `tee` < `strongbox`/`fido2_hw`/`hsm`; at equal
rank only the same kind replaces, and never by dropping the UV bit. A
registration that would weaken the record is ignored without error.

### Android key attestation of the instance key (stage B2)

`POST /wallet-provider/wia/generate` accepts an optional `key_attestation`
object, evidence about the **instance (PoP) key** itself:

```json
{"pop": "...", "challenge": "<C>",
 "key_attestation": {"type": "android_key", "x5c": ["<base64 DER leaf>", "<intermediate>", "<root>"]}}
```

`type` selects a verifier from a registry (`android_key`; `app_attest_assertion`
is registered by its own stage). The request is classified as follows:

| Situation | Result |
|---|---|
| field absent | no instance-key evidence, home `unknown` |
| `type` not registered | HTTP 400 `KEY_ATTESTATION_TYPE_UNSUPPORTED`, before the single-use challenge is consumed |
| evidence invalid (malformed, broken chain, expired certificate, wrong leaf key, wrong challenge, missing attestation extension, revoked certificate) | WIA refused, HTTP 400 `KEY_ATTESTATION_INVALID` (same rule as a failing native attestation) |
| the evidence cannot be judged (no fresh revocation list) or a verified record cannot be stored (storage outage) | WIA refused, HTTP 503 `KEY_ATTESTATION_UNAVAILABLE`, nothing recorded |
| sound but names no home (see below) | no record; the WIA issues with the home `unknown` |
| verified hardware-backed | record written, home `strongbox` or `tee` |

**Challenge.** The WIA challenge C is reused. The key must have been generated
with the attestation challenge

    SHA-256( "siros-instance-key-v1" || C )

where C is the challenge string exactly as `POST /wallet-provider/wia/challenge`
returned it (base64url without padding, taken as its UTF-8 bytes, **not**
decoded) and `||` is plain concatenation. The result is 32 bytes
(`setAttestationChallenge`). The WIA challenge is single use, so evidence cannot
be replayed under another challenge.

**What the verifier checks** (`internal/service/android_key_attestation.go`):

1. the x5c list (base64 DER, leaf first; at most 8 certificates, 8 KiB each,
   32 KiB in all) links up: names chain, every signature verifies, every issuer
   is a CA;
2. the chain verifies at submission time to a **pinned** anchor. The anchors are
   only those the operator configured: the backend ships none, uses no operating
   system pool and never fetches roots itself. The root may be omitted from the
   x5c;
3. the leaf's `KeyDescription` extension (OID `1.3.6.1.4.1.11129.2.1.17`) is
   parsed (unknown tags and versions are skipped, hostile ASN.1 is bounded);
4. the leaf's public key equals the PoP key (P-256), and `attestationChallenge`
   equals the value above;
5. both `attestationSecurityLevel` and `keymasterSecurityLevel` are
   TrustedEnvironment or StrongBox; the home is the weaker of the two
   (StrongBox -> `strongbox`, otherwise `tee`). Anything else (software) names
   no home;
6. from the hardware-enforced list: `origin` is GENERATED and `purpose`
   includes SIGN (otherwise no home); `algorithm`/`ecCurve`, when present, are
   EC/P-256 (otherwise invalid);
7. the `attestationApplicationId` has at least one signing-certificate digest
   and every digest is on `allowed_app_digests` (and, if `allowed_packages` is
   set, every package is listed); otherwise no home;
8. last, and only for evidence that would otherwise be accepted: no certificate
   of the chain is listed in Google's status list
   (`https://android.googleapis.com/attestation/status`). The list is cached
   for its `Cache-Control: max-age` (default `status_list_default_ttl_seconds`,
   at most 24 h) **minus the age the response already had** (the `Age` and
   `Date` headers, RFC 9111), and **never used past that**: a response already
   past its max-age is refused, and when the cached list has expired and cannot
   be fetched, evidence is refused (HTTP 503) and nothing is recorded. One
   refresh runs at a time, callers waiting for it share its result (a failure
   too) and honour their own cancellation, and a failed refresh is remembered
   for 5 s so an outage does not cost every request a timeout.

A chain that does not end in a pinned anchor names no home (it is not an
error: the device may simply be one the operator does not trust). With no
anchors or no allowed app digests configured the verifier is **fail closed**:
it ignores every submission (no record, home `unknown`) and the server logs a
warning at startup.

`verifiedBootState`, `deviceLocked` and `osPatchLevel` are **recorded, never
required**: the record carries `verified_boot_state` (`verified`, `self_signed`,
`unverified`, `failed`), `device_locked` and `patch_level`, the `instance_key`
slot carries `boot`, and policy decides what to do with them.

On success the record (`kind android_key`, `home`, `security_level`,
`verified_boot_state`, `device_locked`, `patch_level`, `app_digest`,
`chain_fingerprint`, `chain_not_after`, `verified_at`) is written under the PoP
key's thumbprint through the store, which never replaces it with weaker or
absent evidence. The instance's `wscd_type` follows from the record's home
(`native_android`), and the verified slot is rendered by the `android_key`
builder:

    (instance_key (kind android_key)(home strongbox|tee)(level L)(boot B)(binding attested))

Instance-key records never feed Key Attestation: neither the policy's `fido2`
slot nor the legacy trust gate (used when the policy is disabled) accepts a
record whose kind is not `fido2`, so an `android_key` record cannot unlock
client-selected `key_storage`, `user_authentication` or certification claims
for a credential key. Nothing the client reports is copied into a verified atom. Later WIAs of the same
key need no new chain: the stored record is looked up by the PoP key's
thumbprint, and the fresh PoP proves possession. Periodic re-checking of stored
records against the status list is not done yet (`chain_not_after` and
`verified_at` are recorded for it).

**Configuration** (`wallet_provider.attestation.android_key_attestation`):

| Key | Environment | Meaning |
|---|---|---|
| `trust_anchors_path` | `WALLET_WALLET_PROVIDER_ATTESTATION_ANDROID_KEY_ATTESTATION_TRUST_ANCHORS_PATH` | file of PEM CERTIFICATE blocks (pinned roots) |
| `trust_anchors_pem` | `..._TRUST_ANCHORS_PEM` | the same, inline; added to the file's |
| `allowed_app_digests` | `..._ALLOWED_APP_DIGESTS` | SHA-256 of the app signing certificate(s), hex (colons allowed), comma separated |
| `allowed_packages` | `..._ALLOWED_PACKAGES` | optional package-name restriction |
| `status_list_url` | `..._STATUS_LIST_URL` | default Google's status list |
| `status_list_default_ttl_seconds` | `..._STATUS_LIST_DEFAULT_TTL_SECONDS` | freshness when the response has no `max-age` (default 3600) |

Get Google's attestation roots from <https://android.googleapis.com/attestation/root>
(a JSON array of PEM certificates; it includes the RSA root and the ECDSA P-384
"Key Attestation CA1" root), review them, and pin them. The server refuses to
start on an anchors file or digest it cannot parse, including a malformed PEM
block between valid ones (a partly read trust list is never used).

Tests build synthetic chains (a test root, an intermediate and a hand-encoded
`KeyDescription`). `TestAndroidKeyAttestation_RealPixelChains` verifies real
chains from `internal/service/testdata/android/` when they are captured (see its
README); it is skipped until then.

## Preview endpoint

`POST /wallet-provider/assurance-preview` (same authentication, audience and
`w` permission as `/key-attestation/generate`; rate-limited like the WIA
routes) lets a wallet learn what it would get before it asks for a Key
Attestation or a WIA. It runs the **same verifier** and the **same assessor**
in dry-run mode: nothing is stored, no attestation is issued, no decision
metric is recorded. No rules or rule text are returned.

Request (every field optional):

```json
{
  "wallet_instance_id": "<jkt>",
  "jwks": [ {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."} ],
  "security_properties": { "key_storage": ["hardware"], "plugin": "fido2" },
  "fido2_attestation": { "attestation_object": "<base64url>", "client_data_hash": "<base64url>" }
}
```

Response:

```json
{
  "key_storage": ["iso_18045_moderate"],
  "user_authentication": ["iso_18045_basic"],
  "certification": "none",
  "wia_profile": "platform_attested",
  "wia_issue": true,
  "policy_version": "<sha256>",
  "schema_version": 2,
  "assurance_enabled": true,
  "fido2_verified": true
}
```

* `fido2_attestation` is verified by `FIDO2AttestationService` exactly as at
  registration (a failure is `400` `ATTESTATION_INVALID`) but never stored.
  When it is the only key information the attested key is the batch; with
  `jwks`, stored records cover the other keys. If FIDO2 verification is not
  enabled on this backend, the submission cannot be verified and counts for
  nothing (`fido2_verified: false`); everything the caller merely states is
  claimed evidence.
* `wallet_instance_id` must be an active instance of the caller (same tenant
  and user) whose last attestation is within the WIA lifetime; otherwise `404`, indistinguishable from an unknown instance. Its
  stored platform source is what the WIA part of the preview assumes ("the
  wallet attests the way it did last time"); without an instance the WIA
  baseline `backend_attested` is assumed. The WIA part never sees the FIDO2
  submission, as a real WIA request does not.
* With the policy disabled the response is what the legacy path produces
  (`assurance_enabled: false`, empty `policy_version`, `wia_issue: true`,
  `wia_profile` the source a WIA would carry today).

## Linting

`assurance-lint -rules <file>` (or `-config <backend config>` to use its
schemes and catalogue) prints findings and exits 1 on any error. The same
checks run at startup; lint errors refuse to start, warnings are logged.

* **ERROR** a rule that is not a list, an unknown dimension tag (the known
  ones are `assure-ks`, `assure-ua`, `assure-cert`, `assure-wia`,
  `assure-wia-issue`, `assure-wia-cert`), a slot order
  that is not canonical (the rule could never match), a missing or duplicate
  id, an unloadable line.
* **WARN** no `assure-wia-issue` rule at all (every WIA would be refused), an
  `assure-wia` profile or `assure-wia-cert` name outside the configured scheme
  or catalogue.
* **WARN** a rule whose `(claimed ...)` group has children (naming the rule
  id), a tier or certification name outside the configured scheme or
  catalogue, an open grant (`*`, prefix, range), an emitted value that is not
  a registered OpenID4VCI key storage / user authentication value.

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

* `deploy/assurance/production.rules.example`: verified-evidence rules, with
  placeholder AAGUIDs: key storage by AAGUID, user authentication by AAGUID
  **and `(uv present)`**, `wia-issue-all` (today's behaviour), an S1 rule for
  `platform_attested`, and a commented `assure-wia-cert` example.
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
* the backend refuses to start if the file is missing or fails lint;
* the rules must contain an `assure-wia-issue` rule (for example
  `# id: wia-issue-all` / `(assure-wia-issue (evidence))`), or every WIA is
  refused.

The sirosid-dev Helm chart does **not** support this yet. Its ConfigMap and
volume mount for the rules file are pending; until they exist, the file has
to be provided by other means.
