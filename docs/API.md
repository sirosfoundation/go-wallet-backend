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

Most endpoints require a JWT token in the `Authorization` header:

```
Authorization: Bearer <token>
```

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

#### POST /user/webauthn/register/start

Start WebAuthn registration (passwordless).

**Request:**
```json
{
  "username": "alice",
  "display_name": "Alice Smith"
}
```

**Response:**
```json
{
  "options": {
    "publicKey": {
      "challenge": "...",
      "rp": {...},
      "user": {...},
      "pubKeyCredParams": [...]
    }
  }
}
```

#### POST /user/webauthn/register/finish

Finish WebAuthn registration.

**Request:**
```json
{
  "credential": {
    "id": "...",
    "rawId": "...",
    "response": {...},
    "type": "public-key"
  }
}
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "did": "did:key:..."
}
```

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
   itself fails the write is taken back too (fails closed, `5xx`).

Why that is enough: take a write W, its re-read R, and an erasure's cut-off
advance A followed by its sweep S. If R sees A, W removes itself. Otherwise
R < A, so W < A < S and S, which lists after A, finds W and deletes it.
`DELETE /user` additionally takes the cut-off with a compare-and-set
(`UserStore.InvalidateAuthBeforeForToken`, one conditional write in the store):
a lifecycle revocation that lands between the request's last check and the
advance makes the deletion answer `401` and delete nothing irreversible, while
a cut-off left by an earlier attempt of the same deletion (a replaced token)
still lets a fresh login retry.

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
/user/session`: it drops every session, erases the wallet data, stored
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
found nothing outstanding. The one case that can no longer be retried by the
user is a session store that fails on its second pass, after that revocation:
the record is kept and the error is returned, but the user's own tokens are
refused from then on until the process restarts, so an operator has to finish
it. Pending challenges, invite references and membership rows are removed on a
best-effort basis.

The last step is a sweep of holder data after the user record is removed, for
a credential or presentation that a token issued after the token cut-off wrote
while the deletion ran. It can only be sound once the record is gone (the
deletion tombstone then refuses every write), so it cannot hold the record
back. If it fails, the answer is `202` with `DELETION_CLEANUP_PENDING` and
`"result": "DELETED"`: the account **is** deleted, repeating the request is
pointless (the token is refused and the account is unknown), and an operator
clears the remainder. The leftover is not served to any token.

### Credential Management

All credential endpoints require authentication.

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
