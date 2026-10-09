# ADR-013: Credential Status Checking Lives Outside the Engine

| Status | Decision Date | Refs |
|--------|--------------|------|
| **ACCEPTED** | 2026-10-09 | #192, PR #423 |

## Context

The wallet should know when a credential was revoked or suspended (IETF Token
Status List, `status.status_list` in the credential). The first design (PR #423
before 2026-10-09) fetched and verified the status list **inside the OpenID4VP
engine, at presentation time**, and could refuse to present.

Review feedback of 2026-10-09 rejected that:

- **Latency.** Every presentation paid for a fetch, a signature verification
  and a go-trust call, in the one interaction the user is waiting for.
- **Availability.** If the list host is unreachable, or the wallet is offline,
  presentation was either blocked (strict modes) or had to fall back to
  "log and proceed" (soft modes), which is a check that does not check.
- **Engine scope.** The engine is the security and privacy sensitive part of the
  backend. Fetching attacker-influenced URLs, parsing JOSE/COSE and
  caching lists there adds attack surface and logic to the component that
  should do the least.

## Decision

1. The engine does **not** check credential status. The presentation path
   neither fetches a status list nor can be refused by one. The
   `presentation.status_check*` modes and the `CREDENTIAL_REVOKED` /
   `CREDENTIAL_STATUS_UNDETERMINED` engine codes are removed (they never
   shipped on main).
2. Clients (web frontend, Kotlin SDK, Swift SDK) check status **in the
   background**, ahead of need, by calling a backend API:
   `POST /status/v1/lists` (see [API.md](../API.md)). The verifier code
   (`pkg/statuslist`, signer trust via go-trust) is kept and exposed through
   `internal/service.StatusService`.
3. The client **trusts the backend's verification**. The API returns the
   verified list itself (the original compressed `lst`), and the client
   computes the per-credential state locally. The backend never learns which
   credential or which index is asked about.
4. **Fail closed.** Only a list that is fetched, signature-verified, temporally
   valid and signed by a key go-trust accepts is `verified`. Everything else is
   `undetermined` with a reason. The API has no "valid" state, so no failure can
   be mistaken for one.
5. **Privacy by construction.** List URIs reveal which issuers a user deals
   with. They are never logged (alone or with a user/subject identifier), not
   audited and not stored per user; the service receives the tenant, not the
   user; the only state is a tenant+URI keyed cache of public data. Clients are
   asked to send one to three lists per request at randomized times; the server
   only enforces a cap.
6. Authenticated callers only for now (no anonymous token), rate limited per
   caller.

## Consequences

- Presenting never depends on a status list. A revoked credential can still be
  presented until the client's background check has noticed; the verifier
  remains responsible for the authoritative check, as before.
- Status is only as fresh as the clients' refresh schedule and the lists' `ttl`
  (capped at one hour in the backend cache).
- The backend sees "this authenticated caller asked for some list" (rate
  limiting) and the list URIs in transit, but keeps neither together.
- Clients must implement the entry lookup (documented in API.md) and the
  fail-closed rule.
- `status_check.*` configuration replaces the removed `presentation.status_*`
  keys; the go-trust requirements of [ADR-012](012-trust-evaluation-architecture.md)
  (`status-list-signer` policy) are unchanged.
- Anonymous (identity-free) access could be added later with its own token
  audience, without changing the response format.
