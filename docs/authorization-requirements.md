# Authorization requirements: aud, tac, and acr per call

This is the client-facing reference for what token properties (`aud`, `tac`,
`acr`) each API call requires. Use it to decide what to request from
`POST /auth/token` before making a given HTTP or WebSocket call, without
having to read the enforcement source (`internal/server/providers.go`,
`internal/engine/session.go`, `pkg/middleware/tokenauth.go`).

For the full token-issuance design and rationale, see `docs/new-as.md`.

## The three properties

| Property | What it is | Who sets it |
|---|---|---|
| `aud` | Which audience (purpose) the token is scoped to - e.g. `wallet-backend` (general use) or `wallet-registry` (identity-free trust-evaluation/engine calls). | **You request it** - the `aud` field in the token request body. |
| `tac` | Token Access Control - a string of permission characters (`r` read, `w` write, `l` list, `i` insert, `d` delete, `k` delegate, `a` admin) capping what the token can be used for. | **You request it** (optional) - the `tac` field in the token request body. Defaults and caps depend on the request shape (see below). |
| `acr` | Authentication Context Class Reference - proof of *how* the underlying session was authenticated (e.g. passkey). | **Never client-supplied.** Inherited automatically from your session (or, for delegation, from the parent token). Every token the AS mints always has one - there is no way to request a token without an `acr`. |

`tac` is a set, not a single value: a route requiring `w` is satisfied by a
token with `tac: "rwl"`, not just `tac: "w"` - request the narrowest set
that covers everything you intend to call with that token.

## Getting a token: `POST /auth/token`

Request body:

```json
{
  "aud": "wallet-backend",
  "tenant_id": "optional, defaults to your session's tenant",
  "tac": "optional, see defaults below",
  "anonymous": false
}
```

How the request is authenticated determines which of three shapes you get:

| Shape | How to trigger it | `sub` (identity) in the issued token | `tac` if omitted | `tac` cap |
|---|---|---|---|---|
| **Session** | Session cookie present, `anonymous` omitted/false | Your user ID | Your session's `MaxTAC` | Must be a subset of your session's `MaxTAC` |
| **Anonymous** | Session cookie present, `anonymous: true` | *(omitted)* | `r` | Must be a subset of `rl` (read-only), **and** a subset of your session's `MaxTAC` |
| **Delegation** | `Authorization: Bearer <parent token>` header, no session cookie | Same as the parent token's `sub` | Parent's `tac` minus `k` (delegate) | Must be a subset of the parent token's `tac` (any subset, including `w`/`i`/`d`/re-delegating `k` - not capped to read-only) |

Notes:
- **Anonymous ≠ unauthenticated.** It still requires a real, valid session
  with a non-empty `acr` - it only means the issued token omits `sub`, e.g.
  for a privacy-preserving trust-evaluation call you don't want tied to
  your identity. A session-less caller never reaches this path.
  Anonymous requests also can't target a different tenant than your own
  session's tenant (unless your session is itself cross-tenant, `"*"`).
- **Delegation** is for minting a downscoped token to hand to another
  party/service. It requires the parent token to have `k` (delegate) in
  its `tac`. The delegated token's `tenant_id` must match the parent's
  (or narrow from `"*"`).
- `tenant_id`, if you set it explicitly, must equal your session/parent's
  own tenant, unless that session/parent is cross-tenant (`"*"`).

## HTTP routes

All of these require `aud: "wallet-backend"` unless noted otherwise. All
require a valid token (session or delegation) via `Authorization: Bearer`
or session cookie as appropriate for the route group.

| Method | Path | Required `tac` | Notes |
|---|---|---|---|
| GET | `/user/session/account-info` | `r` | |
| POST | `/user/session/settings` | `w` | |
| GET | `/user/session/private-data` | `r` | |
| POST | `/user/session/private-data` | `w` | |
| DELETE | `/user/session` | `d` | |
| POST | `/user/session/webauthn/register-begin` | `i` | |
| POST | `/user/session/webauthn/register-finish` | `i` | |
| POST | `/user/session/webauthn/credential/:id/rename` | `w` | |
| POST | `/user/session/webauthn/credential/:id/delete` | `d` | |
| GET | `/issuer/all` | `l` | |
| GET | `/issuer/:id/metadata` | `r` | |
| GET | `/verifier/all` | `l` | |
| POST | `/helper/get-cert` | `r` | |
| POST | `/proxy` | `r` | Only registered if `features.proxy_enabled` |
| GET | `/keystore/status` | `r` | |
| POST | `/wallet-provider/key-attestation/generate` | `w` | |
| POST | `/wallet-provider/wia/challenge` | `w` | |
| POST | `/wallet-provider/wia/generate` | `w` | |
| POST | `/wallet-provider/fido2-attestation/register` | `w` | Only registered if `wallet_provider.attestation.fido2_attestation.enabled` |
| GET | `/storage/vc` | `l` | |
| POST | `/storage/vc` | `i` | |
| POST | `/storage/vc/update` | `w` | |
| GET | `/storage/vc/:credential_identifier` | `r` | |
| DELETE | `/storage/vc/:credential_identifier` | `d` | |
| POST | `/v1/evaluate` | `r` | **`aud`: `"wallet-registry"` or `"wallet-backend"`** - this is the intended anonymous-token call. |
| POST | `/v1/resolve` | `r` | Same `aud` as `/v1/evaluate`. |

Public, unauthenticated routes (registration, login, tenant config,
`/helper/auth-check`) aren't listed - they need no token at all. Admin
routes (`/admin/*`) aren't listed either - they use a separate static-secret
mechanism on a different port, unrelated to `aud`/`tac`/`acr` entirely.

## Engine transport (flow actions)

The engine (credential issuance/presentation flows) enforces `aud` at
connection time and `tac` per flow action. This is enforced at the
transport-independent layer inside go-wallet-backend - `Manager.validateToken`
(token → identity/tac), `Session.TAC`, and `handleFlowStart`'s
protocol-keyed check all operate on parsed Go values (a token string in,
a `*Session`/`*FlowStartMessage` domain struct out), not on any particular
wire format. Any transport that authenticates a token into a `Session` and
dispatches a `FlowStartMessage` gets the same enforcement automatically.

**Currently implemented: the legacy WebSocket protocol**
(`wss://{backend}/api/v2/wallet`, see `docs/websocket-protocol-spec.md` for
the full message format). Connecting (`{"type": "handshake", "app_token":
"<token>"}`) requires `aud: "wallet-registry"` or `aud: "wallet-backend"` -
the same as `/v1/evaluate`/`/v1/resolve`. This is exactly the anonymous-token
use case: most wallet clients connect with an anonymous, identity-free
token here.

**Per flow**, once connected, starting a flow additionally requires a
specific `tac` depending on which protocol you're starting - checked
against the same token's `tac`, not re-requested:

| Protocol | Action | Required `tac` |
|---|---|---|
| `oid4vp` | Presenting an existing credential | `r` |
| `oid4vci` | Receiving a new credential | `i` |

A token requested with only `tac: "r"` (the anonymous default) can present
credentials but cannot receive new ones - request `tac: "ri"` (or broader)
if your client needs to do both over the same connection.

WMP (an alternative wire protocol for the same engine transport) is
tracked in a separate PR and will document its own connection details
there when it lands - the `aud`/`tac` requirements in this section apply
to it unchanged, since they're enforced at the shared layer described
above, not in any transport-specific message parsing.

## Legacy tokens

Deployments without the AS enabled (`cfg.AS.Enabled: false`, legacy HMAC
tokens) have no `tac`/`acr`/multi-`aud` concept at all - none of the checks
above apply there. This reference only describes the new-style AS token
model.
