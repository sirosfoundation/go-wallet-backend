# API Reference

This document describes the public wallet API. For the internal administration API, see [Admin API (OpenAPI)](./openapi-admin.yaml).

## Base URL

```
http://localhost:8080
```

## Admin API

The admin API runs on a separate port (default: 8081) and provides multi-tenant management capabilities:

- Tenant management (CRUD)
- User membership management
- Issuer configuration per tenant
- Verifier configuration per tenant

See [openapi-admin.yaml](./openapi-admin.yaml) for the complete OpenAPI 3.0 specification.

## Authentication

Most endpoints require an access token issued by the Authorization Server in the `Authorization` header:

```
Authorization: Bearer <token>
```

Access tokens are short-lived, asymmetrically signed (ES256/ES384/EdDSA) JWTs. A client obtains one
by authenticating with a passkey (or OIDC) in **session mode** and then calling the token endpoint:

1. `POST /auth/passkey/login/begin` and `POST /auth/passkey/login/finish` (registration:
   `/auth/passkey/register/{begin,finish}`) with the header `X-Token-Mode: session`. The
   finish step sets the `__Host-session` cookie; the body carries no token.
2. `POST /auth/token` (with the session cookie) returns an access token for a given
   audience; keys are published at `/auth/.well-known/jwks.json`.
3. `DELETE /auth/session` ends the session.

The legacy HS256 `appToken` flow (`/user/register-webauthn-*`, `/user/login-webauthn-*`,
`/user/session/refresh`, requests without `X-Token-Mode: session`) was removed and answers
`410 {"error":"legacy_tokens_disabled"}`; HS256 bearer tokens are rejected with 401. See
[new-as.md](new-as.md#removal-of-the-legacy-as).

## Endpoints

### Status

#### GET /status

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "service": "wallet-backend"
}
```

---

### User Management

#### POST /user/register and POST /user/login

Removed. Password authentication no longer exists; both endpoints return
HTTP 410 Gone. Use the WebAuthn endpoints below.

#### POST /auth/passkey/register/begin and POST /auth/passkey/register/finish

Passwordless WebAuthn registration. Send `X-Token-Mode: session` (and `X-Tenant-ID` for a tenant).
`begin` returns `{"challengeId", "createOptions": {"publicKey": {...}}}`; `finish` takes
`{"challengeId", "credential": {...}, "displayName", "privateData"}` and, on success, creates an
AS session (cookie) and returns `{"uuid", "displayName", "tenantId", "tenantDisplayName"}`.

#### POST /auth/passkey/login/begin and POST /auth/passkey/login/finish

Same shape for login: `begin` returns `{"challengeId", "getOptions": {"publicKey": {...}}}`;
`finish` takes `{"challengeId", "credential": {...}}`, sets the session cookie and returns the same
body as registration.

---

#### Wallet instance lifecycle (SID-AUTH-06)

A wallet instance is one wallet installation, identified by the JWK thumbprint of
its instance key and registered when it first obtains a Wallet Instance
Attestation. A user can inspect and manage their own instances; a provider
manages them through the admin API (`/admin/tenants/{id}/instances`). There is
one lifecycle and one transition in it: `active` → `revoked`. Revocation cannot
be undone.

That is the ARF's model, not a simplification of it. The ARF gives a Wallet
Unit four states - Installed, Operational, Valid, Revoked - and says "Wallet
Units can only be revoked" and "Revocation cannot be undone". Suspension
exists in the ARF for Wallet Solutions, for PID and Attestation Provider
registrations and for Relying Party registrations, never for a unit, and the
status lists defined for Wallet Instance Attestations carry no value other
than `revoked`. A reversible instance state would therefore mean nothing to a
relying party.

Revoking an instance drops the user's live sessions and refuses new WIAs for
it. Login with the passkey linked to a revoked instance is refused with `403
WALLET_REVOKED`; the user's other, live devices still log in.

Deployments upgraded from a release that still had the reversible `suspended`
state keep those records: nothing writes that status any more, but one already
in the database is read as **blocked, not live**. Its passkey does not log in,
it cannot obtain a WIA, and it does not keep a wallet from being deactivated.
Revoking it is allowed - it is the only way to move it - so an operator can
close it individually or with a revoke-all. Reading it as live instead would
have handed every suspended device back the login a provider took away.

##### Scope of the cut-off

A lifecycle change is about one wallet instance, but the token cut-off and the
session drop it triggers are about the whole user: every device of that user
is signed out and has to authenticate again. The other, non-revoked devices
log in again immediately - that is the "still log in" above - but they do not
keep the session they had.

This is wider than the change that caused it, and deliberately so rather than
by oversight. A bearer token carries the user, the tenant, an `iat` and a
`jti`, and a session record carries the user and the tenant; neither says
which wallet instance it belongs to, and the gate has one cut-off instant per
user to compare them against. Narrowing the cut-off to the affected device
with no such identity would simply stop cutting it off: its already-issued
token would keep working until it expired, and no check after login looks at
instance status, so that device could keep starting issuance and presentation
flows. Signing the user out everywhere is the only sound approximation the
data supports.

Narrowing it properly needs the instance identity to survive login - carried
on the session and in the token, with the cut-off recorded per instance - at
which point revoking one device would leave the others' sessions alone. That
is a design change, not a bug fix, and it is open.

Wallet instances are per tenant. Revoking the last non-revoked instance of a
user in a tenant deactivates the wallet in that tenant: the credentials and
presentations held there are erased, every passkey of the user is refused at
login in that tenant (`403 WALLET_REVOKED`), and a new enrollment is required.
The user-level data shared across tenants - the encrypted private data (the
custodian of the wallet's keys) and pending challenges - is erased once no
non-revoked instance remains in any tenant the user belongs to.

A login refusal carries three fields, and only two of them are for the client
to act on:

```json
{ "error": "WALLET_REVOKED", "scope": "instance", "message": "..." }
```

`error` is the stable code (`WALLET_REVOKED`) and `scope` says what the
refusal is about:

| `scope` | meaning |
| --- | --- |
| `instance` | This device is revoked. The wallet still exists and the user's other devices answer for themselves at their own login. Server-side data may not be untouched: if this was the last live instance *in this tenant*, that tenant's stored credentials and presentations are already erased, and only the shared user-level data is kept because a live instance remains elsewhere. |
| `wallet` | The wallet is deactivated: no live instance of it is left, its credentials and presentations here have been erased, and a new enrollment is required. |

`WALLET_REVOKED` means both cases, because it has since the first release, so
`scope` is what separates them. `message` is for display only: no client
decision may depend on reading it.

Both scopes are about the tenant the login was for, since wallet instances
are per tenant and so is the refusal. For a user who belongs to more than one
tenant, `scope: "wallet"` says this wallet cannot be opened in this tenant; it
does not say that nothing of the user's remains anywhere. The data shared
across tenants - the private data that holds the wallet's keys, and pending
challenges - is erased only once no non-revoked instance remains in any of
that user's tenants, so a user still live in another tenant keeps it and
keeps logging in there.

##### Why the login gate is where a blocked instance is stopped

Refusing login for the passkey linked to a revoked instance is
the only enforcement in the backend that knows *which* wallet instance is
acting. It is not a duplicate of the WIA gate, and removing it as one would
open a hole.

A wallet instance is identified by its key, and the backend sees that
identity when the instance asks for a WIA - and at login, through the passkey
linked to it. Nowhere else: an access token carries the user, the tenant, an
`iat` and a `jti`, a WebSocket session carries the user, the tenant and the
handshake token's `iat`, and no issuance or presentation flow checks instance
status. The WIA gate refuses a blocked instance an attestation, which
external parties that require client attestation act on, but this backend
never demands a WIA of its own. A blocked instance that could log in would
therefore still be able to open a session and run issuance and presentation
flows here.

ARF v3 puts a revoked Wallet Unit in a state where the user can still view
what it holds and loses only issuance and presentation, which would mean
refusing at login only for a deactivated wallet. Getting there means carrying
the instance identity past login and refusing issuance and presentation where
they happen - the same prerequisite as scoping the cut-off, above. Until then
the gate stays where it is, and the cost is stated plainly: the user cannot
log in from a revoked device to look at what it holds.

##### Why revoking the last instance erases (a SIROS decision)

Erasing the wallet data when the last non-revoked instance goes is a product
decision, not a requirement. ARF v3 has a Wallet Unit reach its terminal
Revoked state without losing anything: the user can still view the
attestations and the transaction log they hold, and what they lose is
issuance and presentation. Erasure goes further than that, so it is recorded
here rather than presented as conformance.

It is kept because in this backend erasure is not what ends the user's
access - the login gate is. Once no non-revoked instance remains, every
passkey of that user is refused at login and a new attestation is refused as
well, so nothing can read the data any more whichever way the wallet got
there. Keeping it would retain key material and credentials for a wallet that
can never be opened again, which is a liability and no benefit to anyone.

Tying erasure to an explicit "deactivate my wallet" alone would also make
retention depend on the order of clicks: a user who revokes three devices one
at a time would end in exactly the same unusable state as a user who pressed
revoke-all, with the data kept in one case and erased in the other. There is
no distinction there worth holding data for.

The trade-off is real and is tied to the login gate: if login is ever
narrowed to refuse only a deactivated wallet - so a revoked instance could
still log in and read what it holds, which is what the ARF's Revoked state
describes - then this trigger has to be revisited in the same change, because
erasure would then be taking away something the user could otherwise still
see.

The status change is recorded before the cascade runs. If dropping sessions or
erasing data then fails, the status change stands and the request answers
`409 ERASURE_INCOMPLETE` (with the new `status`); repeating the same request
re-runs the cleanup, so the administrator retries until it gets `200`.

Revoking an instance also cuts off bearer tokens issued before it: legacy
access and refresh tokens, and access tokens validated by the backend or
accepted for a WebSocket handshake, are refused with `401` when their `iat`
is not after the cut-off, even if they have not expired. No token of that
user is exempt, the one carrying the request included.

Two kinds of token need separate handling, because the cut-off is recorded
against a user. An **anonymous** AS token names no user, so there is nothing to
look up: instead it is refused (`403`) on every wallet-scoped route (account,
configuration, wallet-provider, credential storage, and `oid4vp`/`oid4vci`
engine flows) and is only accepted for registry lookups (`/v1/evaluate`,
`/v1/resolve`, the registry routes, `vctm` flows). A token naming a user whose
**account has been removed** is refused with `401` as well: deleting the
account writes a deletion tombstone, kept until every token that could name the
user has expired (see DEPLOYMENT.md, "Account Deletion Tombstones"), and the
token gate refuses any token whose user has a tombstone. Wallet Instance
Attestation generation refuses it too, so an old token cannot look like a first
enrollment.
The cut-off is recorded right after the status change is persisted, once the
write has confirmed it landed on the record the request read (so a record that
was replaced for another user in between logs nobody out). If recording it
fails, the revocation stays persisted, the request answers 409
`ERASURE_INCOMPLETE`, and repeating it records the cut-off,
so a revoked instance does not keep working tokens once the request succeeds. The user's other devices log in again
afterwards and their new tokens work normally; the revoked instance has no
way back, since revocation cannot be undone. A login or token refresh that races with a lifecycle change is
refused rather than handed a token that would be rejected on first use; the
comparison is at whole seconds, and a token that would fall into the cut-off's
own second is simply minted in the next one. The same cut-off applies at
`POST /auth/token` - to a delegating bearer token and to the session cookie
itself, so a session that outlived the change cannot mint a fresh token - and
is re-checked for an established WebSocket session at every flow start, so it
also holds across separate engine processes or instances.

##### Erasure and requests already in flight

A request the gate admitted just before a cut-off can still be running when
the cut-off lands and the wallet is erased (instance revocation cascade, or
`DELETE /user`). The backend closes that window for stored holder data with an
ordering rule and a post-write check, not with a cross-collection transaction:

1. **Every erasure advances the user's cut-off first and sweeps holder data
   after it.** The lifecycle cascade advances the cut-off before its first
   holder sweep (and again with the key-material erase), and sweeps once more
   after that. `DELETE /user` advances it before its final sweep, and sweeps
   once more after the user record is removed.
2. **A holder write re-reads the cut-off after it is persisted.** Credential
   create (`POST /storage/vc`) and presentation create (`POST /storage/vp`)
   delete the record they just wrote and answer `401` if the token is now
   refused (cut-off advanced, or the account has a deletion tombstone). A
   credential update restores the previous values instead. If the re-read
   itself fails the write is taken back too (fails closed, `5xx`). The
   rollback is conditional on the record this request wrote - its immutable
   store-assigned id and, for credentials, a per-write token - and is one atomic
   conditional store operation (`DeleteIfUnchanged`, `RestoreIfUnchanged`,
   `DeleteByID`), not a delete by `(tenant, holder, identifier)`. If an erasure
   removed the record and a fresh, authorised request recreated the same
   identifier (or updated the record) before the rollback ran, the stale
   request's rollback finds no matching record and leaves the replacement
   alone; the stale request still answers `401`.

Why that is enough: take a write W, its re-read R, and an erasure's cut-off
advance A followed by its sweep S. If R sees A, W removes itself. Otherwise
R < A, so W < A < S and S, which lists after A, finds W and deletes it.
`DELETE /user` additionally takes the cut-off with a compare-and-set
(`UserStore.InvalidateAuthBeforeForToken`, one conditional write in the store):
the advance happens before anything is erased, so a lifecycle revocation that
landed since the request's last check makes the deletion answer `401` with
nothing removed, and one landing later cannot turn the admitted deletion into a
`401` over a half-erased account. The request's own token is refused once the
cut-off is advanced; a retry after an incomplete deletion needs a fresh login
(a token issued after the cut-off passes).

What is **not** guaranteed:

- If the compensating delete of a fenced-out write fails *and* the erasure's
  sweep has already run, the record stays. The request still fails (`401`, and
  the log line has `left_behind=true`), and the next erasure sweep removes it,
  but until then the data is there. This needs two storage failures at once.
- A token issued *after* the cut-off (a fresh login, which must pass so a failed
  deletion can be retried) is not refused by the cut-off, so its write can
  persist after an erasure's first sweep listed the holder. Both erasures
  therefore end with a sweep that follows the last cut-off advance and the point
  where new writes are refused: `DELETE /user` after the user record is removed
  (the deletion tombstone refuses everything from then on), and the lifecycle
  cascade after the key-material erase, which advances the cut-off atomically.
  By then the revocation is persisted, so the login gate refuses new logins and
  refreshes for the wallet, and a login whose gate check predates it fails the
  re-check after it mints its token. A failing final sweep is
  `ERASURE_INCOMPLETE` (lifecycle, retryable by repeating) or, for `DELETE
  /user`, `202 DELETION_CLEANUP_PENDING` (the account is already gone). What
  remains: a write by a token that is valid after the lifecycle cascade's last
  sweep, which needs a login the gate lets through for that wallet - a user with
  no wallet instance at all in the tenant being logged into (a first enrollment,
  which the gate does not refuse) - and that write is not swept until the next
  erasure.
- Delete and update-in-place operations are not fenced beyond the admission
  check: they cannot create data, so a late one removes or changes only
  something the erasure is removing anyway.
- Writes that do not go through the credential/presentation services (the
  user record's own fields, passkeys, private data) are covered by the user
  store's write fence (`ErrStaleWrite`), not by this post-write check.
- The check relies on the store returning a record's write to a later read by
  the same process (true of the memory store and of MongoDB reading from the
  primary). A deployment reading from lagging secondaries can miss it.

An engine deployed without the backend role in the same process enforces the
cut-off only when persistent storage is configured; with memory storage it
logs a warning at startup and relies on the token lifetime. There is no
second source of truth for the cut-off, so such an engine opens the
configured storage backend read-only - no default-tenant creation and no index
creation for MongoDB - and its database principal needs read rights on the
`users` and `user_deletion_tombstones` collections only (a token whose user
has no record is checked against the deletion tombstone, and a denied read
fails closed: the token is refused with a storage error). Being unable to open it is deliberately
fatal at startup rather than a warning: an engine that came up with the gate
silently off would accept tokens the lifecycle had already revoked, and
nothing would say so. A deployment that does not want the dependency leaves
`storage.type` empty or `memory`, which is the documented unenforced case
above.

A user's instances that are no longer live are retained as lifecycle
records: they are what keeps login and new attestations refused for that
device. The admin API answers `409 INSTANCE_RETAINED` to `DELETE
/admin/tenants/{id}/instances/{instance_id}` for one of them, which covers a
revoked instance and a legacy `suspended` one alike. A live instance of a
user is refused too, with `409 INSTANCE_OWNED`: hard deletion would skip the
token cut-off, session drop and erasure, and deleting the user's last instance
would leave an empty listing that the login gate reads as an initial
enrollment, letting every passkey log in again. Revoke it instead
(`PUT .../instances/{instance_id}/status`), which keeps the tombstone. Only a
record with no user behind it (a stray attestation record) can be deleted.

The passkey link is recorded when the wallet passes its passkey's base64url
credential id as `credential_id` to `POST /wallet-provider/wia/generate`. It
must be one of the caller's own registered passkeys, or the request is refused
with `403 CREDENTIAL_NOT_OWNED`: the first link recorded for an instance wins,
so an unchecked one could keep the real passkey out of the per-instance login
gate for good.

##### GET /user/session/instances

List the caller's wallet instances in the current tenant. Needs `l` in the
token's TAC, like the other collection endpoints (`/issuer/all`,
`/verifier/all`, `GET /storage/vc`).

**Response:**
```json
{ "instances": [ { "id": "<jkt>", "status": "active", "wscd_type": "native_android", "last_attested_at": "..." } ] }
```

##### POST /user/session/logout-all

End every session of the caller, on this device and on any other, and refuse
the bearer tokens already issued to them. The caller's own token is refused
too - that is what logging out everywhere means - so the client logs in again
afterwards. Nothing is erased.

**Response:** `204`; `401` when unauthenticated; `404` when the user no longer
exists.

##### Revoking an instance

There is no self-service endpoint for it. Revocation cannot be undone, so a
user who revoked the instance holding their last passkey would be locked out
of their own account with no way back (SID-AUTH-06).

This is where the ARF puts it too. The User has a right to obtain revocation
and a channel to ask for it - Art. 5a(9)(a) of Regulation (EU) 2024/1183,
`WURevocation_10`, and `WIAM_06`, which requires the channel to work without
the device - and the Wallet Provider is the party that performs it, after
authenticating the User. Providers do it through `PUT
/admin/tenants/{tenantId}/instances/{instanceId}/status` with
`{"status": "revoked"}`, and can revoke every instance a user has with `POST
/admin/tenants/{tenantId}/users/{userId}/instances/revoke-all`.

The irreversible operation a user does own is removing the account, `DELETE
/user/session` (confirmed with a passkey assertion, see below): it drops every session, erases the wallet data, stored
credentials and presentations, deletes the user's wallet instances so the same
device can enrol again, and removes the user record with its passkeys.

If a wallet instance cannot be removed, the answer is `409
DELETION_INCOMPLETE` and **the account still exists**. That is deliberate. An
instance that outlives its account is permanent damage rather than residue:
records are keyed by the instance-key thumbprint and the passkey link is
write-once, so re-enrolling on that device would be refused for good, and a
deleted user cannot authenticate to ask again. Repeat the request to finish
it, as with `ERASURE_INCOMPLETE` on the lifecycle endpoints.

`DELETION_INCOMPLETE` covers: a wallet instance, stored credential or
presentation that could not be removed; a failed lookup of the user's tenant
memberships, wallet instances or user record; and a session store that would
not drop the user's sessions. In all of these nothing has been revoked for
good yet, so the token the request came on keeps working and the same request
can be sent again. The permanent token revocation (the in-process token
blacklist and the engine's revoked-user set) is applied only after the sweep
found nothing outstanding. The cases that can no longer be retried by the user
are a session store that fails on its second pass, or the final holder-data
sweep failing, after the token blacklist revoked the user for good: the record
is kept, but every token of the user, a fresh login's included, is refused until
the process restarts, so repeating the request cannot work and an operator has
to finish it. The answer is `202` with `DELETION_OPERATOR_REQUIRED` and
`"result": "PENDING"` (the account is not deleted yet, and the caller must not
repeat the request). Where no blacklist revocation took effect, the same
failures remain `409 DELETION_INCOMPLETE`, because a fresh login passes the
token cut-off and can repeat the request. Pending challenges, invite references
and membership rows are removed on a best-effort basis.

The last step is a sweep of holder data after the user record is removed, for
a credential or presentation that a token issued after the token cut-off wrote
while the deletion ran. It can only be sound once the record is gone (the
deletion tombstone then refuses every write), so it cannot hold the record
back. If it fails, the answer is `202` with `DELETION_CLEANUP_PENDING` and
`"result": "DELETED"`: the account **is** deleted, repeating the request is
pointless (the token is refused and the account is unknown), and an operator
clears the remainder. The leftover is not served to any token. The deletion
tombstone remembers the user's tenants and canonical holder DID (cleared once
the final sweep succeeds), so a repeat of the deletion that finds no user record
still sweeps the DID-keyed credentials and presentations in every tenant.

##### POST /user/session/delete-begin

Start deleting the account. The caller must confirm it with a fresh passkey
assertion, so a stolen bearer token alone cannot erase an account. Needs `w` in
the token's TAC (it stores a short-lived challenge); any passkey session
qualifies, including one restricted to `rwl`.

**Response:** `200`
```json
{
  "challengeId": "a1b2c3...",
  "publicKey": {
    "rpId": "wallet.example.org",
    "challenge": { "$b64u": "..." },
    "allowCredentials": [ { "type": "public-key", "id": { "$b64u": "..." }, "transports": ["internal"] } ],
    "userVerification": "required"
  }
}
```
`allowCredentials` lists only the caller's own passkeys; any one of them may
sign. The challenge is bound to the caller and to this action, expires after
120 seconds and is single use: the first `DELETE` that presents it consumes
it, whatever the outcome, except that a `confirm` other than `DELETE` is
refused before the challenge is touched. `400 NO_PASSKEY` when the account has no
passkey (an OIDC-only account cannot confirm this way yet); `401` when
unauthenticated; `404` when the user no longer exists.

##### DELETE /user/session

Delete the account: the operation described above, authorised by the assertion.

**Request:**
```json
{
  "challengeId": "a1b2c3...",
  "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": { "authenticatorData": "...", "clientDataJSON": "...", "signature": "...", "userHandle": "..." } },
  "confirm": "DELETE"
}
```
`credential` is the `PublicKeyCredential` the authenticator returned for the
options of `delete-begin`, serialised like the login `credential`. `confirm`
must be the exact text `DELETE`.

The server checks the typed confirmation, consumes the challenge for the
caller, and verifies the assertion against the caller's own passkeys. A
credential of another user is refused, as is a challenge that was minted for
another user or another action (for example a login challenge). No session or
token is minted. It then runs the deletion unchanged, so `200 {"result":
"DELETED"}`, `202` (`DELETION_CLEANUP_PENDING`, `DELETION_OPERATOR_REQUIRED`),
`409 DELETION_INCOMPLETE`, `401` and `404` mean what they do above. A retry
after `409` needs a fresh `delete-begin` and assertion.

| Status | `error` | Meaning |
|--------|---------|---------|
| 401 | `STEP_UP_REQUIRED` | no body, and `user.delete.require_step_up` is on |
| 401 | `STEP_UP_FAILED` | challenge unknown, already used, minted for someone or something else, or the assertion did not verify; the body was malformed |
| 400 | `STEP_UP_FAILED` | the body is over 1 MiB or could not be read |
| 410 | `STEP_UP_EXPIRED` | the challenge is older than 120 seconds, and less than 10 minutes old (an older one is deleted and reads as `STEP_UP_FAILED`) |
| 400 | `CONFIRMATION_REQUIRED` | `confirm` is not `DELETE`; the assertion is not consumed, so the request can be sent again |

A request with a body is authorised by its assertion alone: it does not need
`d` in the token's TAC. The bodyless request still needs `d`. Passkey sessions
hold `d` under the current defaults (`as.default_max_tac` is `rwlid`, and
`/auth/token` issues the session's maximum when no TAC is requested), so a
default passkey token can still delete an account without an assertion while
`user.delete.require_step_up` is false. Restricting `as.default_max_tac` to
`rwl` makes the assertion the only way for passkey sessions.

**Rollout.** For one release the bodyless `DELETE /user/session` still works,
so the backend can ship before the clients. Set
`user.delete.require_step_up: true` (`WALLET_USER_DELETE_REQUIRE_STEP_UP`) to
refuse it with `401 STEP_UP_REQUIRED` once the clients send the assertion; the
default will flip to true in a later release.

**What is erased and what is kept.** Erased: the user record (private data,
passkeys, external identities), the credentials and presentations in every
tenant, the wallet instances, and all sessions and tokens. Kept: a deletion
tombstone for its retention period (it refuses the user's old tokens) and the
audit log. `202` means an operator completes the last cleanup. Issuers and
relying parties keep their own records; they are not notified.

**Audit.** With `audit.enabled`, `audit.account_events` selects the SET events
`requested` (the assertion verified; `step_up: false` for a bodyless request),
`succeeded` and `cleanup_pending`. The subject is a hash of the user id; no
credential content is recorded. None is emitted by default.

### Credential Management

All credential endpoints require authentication.

#### Adding a passkey to an existing account

`POST /user/session/webauthn/register-begin` and
`POST /user/session/webauthn/register-finish` (token TAC `i`) add a passkey to
the caller's account. An account that already has a passkey needs one of them to
authorise the addition, so a bearer token alone cannot enrol a passkey of its
own. Two WebAuthn ceremonies take place, both answered in the one `finish`
request; the authorising assertion is made first or second, in either order.

**`register-begin` response:** as before (`challengeId`, `createOptions`,
`username`), plus, when the account has a passkey:
```json
{
  "authorization": {
    "publicKey": {
      "rpId": "wallet.example.org",
      "challenge": { "$b64u": "..." },
      "allowCredentials": [ { "type": "public-key", "id": { "$b64u": "..." } } ],
      "userVerification": "required"
    }
  }
}
```
`authorization` has the shape of the `delete-begin` options and is bound to the
same `challengeId`: its challenge is fresh, single use and dies with the
registration challenge (5 minutes). It is absent only for an account with no
passkey yet.

**Known limit.** An account with no passkey (for example one that signs in
only through OIDC) has nothing to authorise with, so the first passkey is added
on the bearer token alone. A holder of a stolen token can therefore enrol the
first passkey of such an account and use it to confirm a deletion.

**`register-finish` request:** as before (`challengeId`, `credential`,
`nickname`, `privateData`), plus `authorization`: the `PublicKeyCredential`
assertion an existing passkey returned for the `authorization.publicKey`
options, serialised like the login `credential`. Required unless
`register-begin` returned no `authorization`.

| Status | `error` | Meaning |
|--------|---------|---------|
| 401 | `ENROLLMENT_AUTHORIZATION_REQUIRED` | the account has a passkey and `authorization` is missing |
| 401 | `ENROLLMENT_AUTHORIZATION_FAILED` | the assertion is not from one of the caller's passkeys, is over another challenge, or does not verify |

The check comes before the registration is verified, and a refused attempt
consumes the challenge: start again with `register-begin`.

#### GET /storage/vc

Get all credentials for the authenticated user.

**Response:**
```json
[
  {
    "id": 1,
    "holder_did": "did:key:...",
    "credential_identifier": "urn:credential:123",
    "credential": "eyJhbGciOiJFUzI1NiJ9...",
    "format": "jwt_vc",
    "credential_configuration_id": "UniversityDegree",
    "credential_issuer_identifier": "https://issuer.example.com",
    "created_at": "2023-12-13T10:00:00Z"
  }
]
```

#### POST /storage/vc

Store a new credential.

**Request:**
```json
{
  "holder_did": "did:key:...",
  "credential_identifier": "urn:credential:123",
  "credential": "eyJhbGciOiJFUzI1NiJ9...",
  "format": "jwt_vc",
  "credential_configuration_id": "UniversityDegree",
  "credential_issuer_identifier": "https://issuer.example.com"
}
```

**Response:**
```json
{
  "id": 1,
  "message": "Credential stored successfully"
}
```

#### GET /storage/vc/:credential_identifier

Get a specific credential.

**Response:**
```json
{
  "id": 1,
  "holder_did": "did:key:...",
  "credential_identifier": "urn:credential:123",
  "credential": "eyJhbGciOiJFUzI1NiJ9...",
  "format": "jwt_vc"
}
```

#### DELETE /storage/vc/:credential_identifier

Delete a credential.

**Response:**
```json
{
  "message": "Credential deleted successfully"
}
```

#### PUT /storage/vc/update

Update credential metadata.

**Request:**
```json
{
  "credential_identifier": "urn:credential:123",
  "instance_id": 1,
  "sig_count": 5
}
```

**Response:**
```json
{
  "message": "Credential updated successfully"
}
```

---

### Presentation Management

#### GET /storage/vp

Get all presentations for the authenticated user.

**Response:**
```json
[
  {
    "id": 1,
    "holder_did": "did:key:...",
    "presentation_identifier": "urn:presentation:456",
    "presentation": "eyJhbGciOiJFUzI1NiJ9...",
    "credential_identifiers": ["urn:credential:123"],
    "audience_did": "did:key:verifier...",
    "nonce": "abc123",
    "created_at": "2023-12-13T11:00:00Z"
  }
]
```

#### POST /storage/vp

Store a new presentation.

**Request:**
```json
{
  "holder_did": "did:key:...",
  "presentation_identifier": "urn:presentation:456",
  "presentation": "eyJhbGciOiJFUzI1NiJ9...",
  "credential_identifiers": ["urn:credential:123"],
  "audience_did": "did:key:verifier...",
  "nonce": "abc123"
}
```

**Response:**
```json
{
  "id": 1,
  "message": "Presentation stored successfully"
}
```

---

### Issuer Registry

#### GET /issuer/all

Get all registered credential issuers.

**Response:**
```json
[
  {
    "id": 1,
    "identifier": "https://issuer.example.com",
    "name": "Example University",
    "url": "https://issuer.example.com",
    "credential_endpoint": "https://issuer.example.com/credential",
    "authorization_server": "https://issuer.example.com/oauth",
    "supported_credentials": ["UniversityDegree", "EmployeeID"]
  }
]
```

---

### Verifier Registry

#### GET /verifier/all

Get all registered verifiers.

**Response:**
```json
[
  {
    "id": 1,
    "name": "Example Verifier",
    "did": "did:key:verifier...",
    "url": "https://verifier.example.com"
  }
]
```

---

### Token Status Lists

#### POST /status/v1/lists

Fetches, verifies and trust-evaluates one or more IETF Token Status Lists
([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/))
on behalf of the client and returns them. Clients (web frontend, Kotlin SDK,
Swift SDK) call this **in the background** to learn whether their credentials
were revoked or suspended. **The wallet engine does not check status when you
present**; see [ADR-013](adr/013-status-checking-outside-the-engine.md).

The client **trusts the backend's verification** and reads its own credential's
entry from the returned list **locally**. The backend never learns which
credential, or which index, a client is interested in, only which list.

Authenticated callers only (`Authorization: Bearer <token>`, audience
`wallet-backend`, `tac` containing `r` when go-tokenauth is enforced); anonymous
tokens are rejected. Rate limited per user (falling back to the tenant), see
`status_check.rate_limit`. OpenAPI: [openapi-status.yaml](openapi-status.yaml).

**Request:**
```json
{
  "lists": [
    { "uri": "https://status.example.org/statuslists/7", "etag": "\"1f2e3d4c5b6a79881f2e3d4c5b6a7988\"" }
  ]
}
```

- `lists`: 1 to `status_check.max_lists_per_request` items (default 20). Over
  the cap: `400 TOO_MANY_URIS`. **Clients should send one to three per request**
  (see Privacy); the server only enforces the cap.
- `uri`: the exact `status.status_list.uri` string of the credential, `https`
  only. A repeated `uri` is collapsed: one result per distinct `uri`, in first-
  occurrence order. A `uri` that is not an acceptable `https` URI (or `http` when the operator allows plain HTTP) gets a result
  with `reason: "uri_not_allowed"` rather than failing the request.
- `etag` (optional): the `etag` of the version the client already holds.

**Response `200`** (partial failure is still `200`; every item stands alone):
```json
{
  "results": [
    {
      "uri": "https://status.example.org/statuslists/7",
      "state": "verified",
      "bits": 2,
      "lst": "eNrbuRgAAhcBXQ",
      "iat": 1790000000,
      "exp": 1790086400,
      "ttl": 900,
      "expires_at": 1790000900,
      "etag": "\"1f2e3d4c5b6a79881f2e3d4c5b6a7988\"",
      "signer_trust": "status-list-signer"
    },
    { "uri": "https://other.example/l/1", "state": "undetermined", "reason": "signer_untrusted" },
    { "uri": "https://third.example/l/9", "state": "not_modified", "etag": "\"...\"", "expires_at": 1790000900, "signer_trust": "status-list-signer" }
  ]
}
```

| Field | Meaning |
|---|---|
| `state` | `verified`, `undetermined` or `not_modified`. **There is no "valid" state**: the response is about the *list*, never a verdict on a credential. |
| `reason` | Only with `undetermined`: `fetch_failed`, `unsupported_media_type`, `signature_invalid`, `signer_untrusted`, `trust_unavailable`, `no_signer_key`, `expired`, `not_yet_valid`, `malformed`, `too_large`, `budget_exhausted`, `list_too_small`, `uri_not_allowed`. |
| `bits` | Bits per entry: 1, 2, 4 or 8. |
| `lst` | base64url (no padding) of the zlib-compressed bit string, **byte-identical to the `lst` of the signed token** (not re-encoded). At most `status_check.max_list_bytes` (default 2 MiB) compressed; a larger list is `undetermined`/`too_large`, never truncated. |
| `iat`, `exp`, `ttl` | The token's claims (unix seconds / seconds); `exp` and `ttl` only when the token has them. |
| `expires_at` | Unix time until which the backend treats this version as fresh (bounded by the token's `ttl`/`exp`, by the list host's `Cache-Control: max-age` and by one hour). Refresh before it. |
| `etag` | Quoted opaque version id: a stable hash of the list URI and the token version, identical for every caller and across refetches of an unchanged token. Send it back as `etag` to get `not_modified` instead of the list. |
| `signer_trust` | The trust action that accepted the signer: `status-list-signer`, or `credential-issuer` when the go-trust fallback applied. |

A list is `verified` only if the backend fetched it, verified its signature
(JWT `x5c`/`jwk`, or CWT `x5chain`), `typ`, `sub` (equal to the `uri`) and
`iat`/`nbf`/`exp`/`ttl`, and the signer key was accepted by go-trust for the
tenant (`status-list-signer`, see [ADR-012](adr/012-trust-evaluation-architecture.md)).
Anything else, including no trust service being configured, is `undetermined`.

When the list host supports it the backend refetches with `If-None-Match`; a
`304` refreshes its cache (the signer trust decision and the token's `exp` are
re-checked first).

**Response headers:** `Cache-Control: private, max-age=<n>` with `n` the
shortest remaining freshness over the returned lists, limited by each list's
`ttl`; `Cache-Control: private, no-store` when any item is `undetermined`;
`ETag` (the list's `etag`) for a single-list response; `Vary: Authorization`.
The `no-cache` headers of the other authenticated routes are deliberately not
applied.

**Errors** (JSON `{"error": CODE, "message": ...}`):

| Status | `error` | When |
|---|---|---|
| 400 | `INVALID_REQUEST` | not a JSON object, no `lists`, an item without `uri`, an over-long `etag`, trailing data |
| 400 | `TOO_MANY_URIS` | more than `status_check.max_lists_per_request` items (response includes `max`) |
| 401 | | missing/invalid token |
| 403 | | token not for audience `wallet-backend`, or lacking `r` |
| 413 | `REQUEST_TOO_LARGE` | body over 128 KiB |
| 429 | `RATE_LIMIT_EXCEEDED` | rate limit; `Retry-After` is set |
| 503 | `STATUS_NOT_SUPPORTED` | `status_check.enabled` is false |

The whole request has a deadline (`status_check.request_timeout_seconds`,
default 8 s, at most 12 s, below the 15 s server write timeout); lists not
finished then are `undetermined`/`budget_exhausted`.

##### Reading a credential's entry (client side)

For a credential with `status.status_list = {idx, uri}`:

1. Decode `lst` from base64url and zlib-inflate it (inflate at most 32 MiB).
2. With `bits` = 1, 2, 4 or 8: `byte = idx * bits / 8` (integer division),
   `shift = (idx * bits) % 8`, `value = (list[byte] >> shift) & ((1 << bits) - 1)`.
   Bits are packed **least significant bit first** within a byte. An `idx` past
   `len(list) * 8 / bits` is an error, not VALID.
3. `value` 0 is VALID, 1 is INVALID (revoked), 2 is SUSPENDED; any other value is
   application specific and **must be treated as not valid**.

**Fail-closed rule:** only `state` `verified` (or `not_modified`, which refers to
a version the client already verified through this API) with an in-range index
and `value` 0 may be shown as valid. `undetermined`, an HTTP/transport error, a
timeout or a malformed answer means **unknown**: show it as unknown, never as
valid, and keep the last confirmed state (do not downgrade a credential to
"revoked" on `undetermined` either: it says nothing about the credential).

##### Recommended client behaviour

- Check in the **background**, never as part of a presentation and never
  blocking one: a presentation must work offline and without this API.
- **One list per request** (at most three). Requesting several lists in one
  call lets the server see which issuers a user's credentials come from
  together; one at a time keeps the call about a single list.
- **Refresh at a randomized time within the `expires_at` window** (for example
  uniformly between 50% and 90% of the time remaining), not on a fixed schedule
  and not at app start for every credential at once. Send the stored `etag`.
- Back off on `429`/`503`/`undetermined`; honour `Retry-After`.
- Do not request lists for credentials that carry no `status.status_list`.

##### Outbound fetch policy

List URIs are chosen by the client, so the backend fetches them like every
other untrusted URL, under the `http_client` settings. By default only HTTPS is
accepted and private, loopback, link-local and cloud-metadata addresses are
refused (on every redirect hop and DNS answer). An operator can relax this for
a test or development deployment with `http_client.allow_http` (plain HTTP),
`http_client.allow_private_ips` (private addresses; this also permits plain HTTP,
see `AllowsPlaintext`) or `http_client.insecure_skip_verify`, each relaxing only
its own restriction. Whatever is fetched is still signature-verified and its
signer trust-evaluated, so a relaxed policy never makes a list `verified`
without the signer being trusted.

##### Privacy properties

Each list URI a user asks for identifies a status list published by a specific
issuer, so asking for it reveals that the user holds a credential from that
issuer (though not which credential, as a list covers many). The backend is
built not to learn or keep that:

- The request is a `POST` body: URIs are not in URLs or access logs.
- URIs are **never logged**, at any level, alone or with a user or subject
  identifier. The service logs counts, outcomes and durations only, and
  errors that may contain a URI are never logged. The go-trust evaluation of the
  signer is redacted the same way.
- **No audit events** are emitted for status lists, and nothing is stored per
  user about which lists were requested.
- The service is handed the tenant, **not the user**; the rate limiter keeps
  a counter per caller, never what was asked.
- The only state is an in-process cache keyed by tenant and URI that holds
  public data (the signed list and its metadata); it cannot say who asked.
- The backend does not learn the credential or the index: clients compute the
  entry locally from the returned list.

---

### Proxy

#### POST /proxy

Proxy a request to an external service.

**Request:**
```json
{
  "url": "https://external-api.example.com/endpoint",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": {...}
}
```

**Response:**
```json
{
  "status": 200,
  "headers": {...},
  "body": {...}
}
```

---

## Error Responses

All endpoints may return error responses in the following format:

```json
{
  "error": "Error message description"
}
```

### Common HTTP Status Codes

- `200 OK` - Success
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Missing or invalid authentication
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `500 Internal Server Error` - Server error
- `501 Not Implemented` - Feature not yet implemented

---

## Rate Limiting

TODO: Rate limiting is not yet implemented.

When implemented, rate limit information will be included in headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1702468800
```

---

## Versioning

The API does not currently use versioning. When versioning is introduced, it will use URL path versioning:

```
/v1/storage/vc
/v2/storage/vc
```

---

## WebSocket API

TODO: WebSocket support for client-side keystores is not yet implemented.

When implemented, the WebSocket endpoint will be:

```
ws://localhost:8080/ws
```

### Message Format

```json
{
  "message_id": "unique-id",
  "action": "sign_presentation",
  "payload": {...}
}
```
