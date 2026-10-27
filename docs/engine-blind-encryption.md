# Engine-blind encryption

Status: draft. The presentation half is implemented by
https://github.com/sirosfoundation/go-wallet-backend/pull/471. The issuance half
is implemented in the engine and merged
(https://github.com/sirosfoundation/go-wallet-backend/pull/469): the engine
passes the client's encryption JWK to the issuer and relays the issuer's JWE
with `decrypt_credential_response`. Clients must implement it; there is no
fallback.

The engine relays ciphertext and never sees credential contents, any secret
the issuer delivers alongside a credential, or a `vp_token`. It still sees metadata: which issuer
or verifier, the public verifier request, timing and sizes. Every key used for
this lives in the client (wallet-frontend, Kotlin SDK, Swift SDK). The change
is made in the engine and the clients together; there is no fallback for
clients that predate it.

## Why

Before this change the engine generated the OID4VCI response-encryption key and
decrypted the issuer's JWE itself, and it built and encrypted the OID4VP
`direct_post.jwt` response. So the engine process, and any TLS terminator in
front of it, saw every issued credential, every presentation and every
issuer-delivered secret in clear. Delivering a secret to the wallet requires
an encrypted issuer response, which made that exposure unavoidable.

## Threat model

The engine passes the wallet's response-encryption key to the issuer and the
verifier's key to the wallet, so a compromised engine can substitute either
one. For issuance and for SD-JWT presentations nothing detects the
substitution. For mdoc, OID4VP Annex B.2.6.2 makes it detectable, because the
verifier key's thumbprint is bound into the session transcript, but only after
the engine has already seen the plaintext. The model is therefore
honest-but-curious: the engine is trusted to relay the right keys but not to
read what it relays (OID4VCI section 13.4 covers this setup). The honest-but-curious wording is not a defence against an actively malicious engine for remote mode; the embedded engine (gomobile, native Kotlin/Swift only, in design) is the planned answer to an active relay on native, while web stays honest-but-curious.

## What the engine still needs

- Issuance: only `transaction_id` and `interval` (to poll a deferred
  credential) or `credential_count` (credentials issued) from the response.
  The client supplies them.
- Presentation: the validated `response_uri` (from `verified_request`) to POST
  to, and the verifier's reply (`redirect_uri`).
- Verifier trust evaluation and the fail-closed request-signature gate stay in
  the engine and run before the client sees a request.

## Issuance (OID4VCI)

1. `sign_request` with `action: "generate_proof"` gains an optional
   `credential_response_encryption: { alg, enc, required }`. The engine
   negotiates the pair from issuer metadata. Supported: `ECDH-ES`,
   `ECDH-ES+A128KW`, `ECDH-ES+A256KW` with `A128GCM`, `A256GCM`,
   `A128CBC-HS256`, `A256CBC-HS512`. It is present when the issuer supports
   response encryption.
2. The client generates a fresh ephemeral P-256 key per `generate_proof`
   request, keeps the private key in memory keyed by flow id, and returns the
   public JWK as `credential_response_encryption_jwk` in the `sign_response`
   (`{kty:"EC", crv:"P-256", x, y, use:"enc", alg}`). Absent means declined; if
   `required` is true the engine fails the issuance.
3. The engine puts the JWK in the credential request's
   `credential_response_encryption` (the request is itself encrypted to the
   issuer's key where the issuer requires it) and sends it.
4. The issuer's JWE reaches the engine, which cannot decrypt it. The engine
   sends `sign_request` with `action: "decrypt_credential_response"` and
   params `{ jwe, deferred }`.
5. The client decrypts, keeps the credentials and the response-level
   `credential_metadata` locally, and answers with only
   one of two mutually exclusive success forms (or `error`):
   `{ transaction_id, interval? }` (deferred) or `{ credential_count }`
   (issued, 1 to 256). A reply with neither, or both, is refused.
6. If a `transaction_id` came back the engine polls the deferred endpoint; each
   answer goes through step 4 again with `deferred: true`. The client keeps its
   key for the whole flow.
7. `flow_complete.credentials[i]` keeps `format`, `vct` and `type_metadata` but
   has no `credential` value; top-level `credential_response_encrypted: true`
   marks it. The client fills entry i from the i-th decrypted credential; a
   count mismatch is an error. For an encrypted response `flow_complete` carries
   no `credential_metadata`. For a plain response the engine may relay only the
   display-only members (`display`, `claims`); extension members are never
   relayed from a plain response (the engine drops them). Clients ignore
   extension members arriving in `flow_complete`.
8. The client sends the `notification_id` itself in `credential_notification`;
   the engine's notification context holds an empty id, which already matches
   any.
9. Seed delivery is gone. The superseded shapes (`org.siros.secret_seed`,
   `org.siros.holder_commitments`, `org.siros.psc`, `secret_members`) are
   refused by the wallet clients, on immediate, deferred and plain
   completions. The replacement is Credential Auxiliary Data (`auxiliary_data`),
   implemented in the engine by
   https://github.com/sirosfoundation/go-wallet-backend/pull/480 (not part of
   this PR; this branch still carries the old engine-side seed handling until
   that PR lands). Whatever the wallet validates and stores from the decrypted
   response stays wallet-side: the only client-supplied answers in the
   encrypted-response relay stay `credential_count` (1 to 256) or
   `transaction_id` (with an optional `interval`), or an `error` whose text the
   engine never logs or relays; the engine never receives auxiliary data from
   the client.
10. If the issuer offers no response encryption, the response is plaintext and
    the engine sees it; that is the issuer's choice.

## Presentation (OID4VP, `response_mode=direct_post.jwt`)

- `sign_presentation` carries `verified_request`
  (`client_id`, `client_id_scheme`, `response_mode`, `response_uri`, `signed`,
  `signature_verification`, `client_metadata`; only `client_metadata` is capped, at `MaxClientMetadataBytes` (64 KB), and the raw request object the engine forwards in `trust_evaluation_request` is capped separately at `MaxRequestJWTBytes` (256 KB)). The client takes the JARM
  `aud` from `verified_request.client_id`. Only the engine POSTs, and only to
  `verified_request.response_uri`.
- `sign_request` also carries, for `direct_post.jwt` only:
  `response_encryption: { jwk, alg, enc }` (the verifier's public JWK with its
  `kid`, selected by the engine: `client_metadata.jwks` `use=enc`, else the
  request JWT's `x5c`; `alg` from the JWK or inferred from the key type; `enc`
  defaults to `A128GCM`) and `state` when the request had one.
- The client returns `response_jwe` instead of `vp_token`:
  - `vp_token`: for DCQL a JSON object `{ "<credential_query_id>": ["<token>", ...] }`,
    otherwise the string.
  - JARM claims: `iss: "https://self-issued.me/v2"`, `aud`, `iat`,
    `exp: iat + 300`, `vp_token`, `state` when present.
  - A compact JWE with the requested `alg`/`enc`, `kid` in the protected header
    (when the JWK has one). Clients SHOULD NOT set `cty`: the JWE plaintext is
    plain JSON claims, not a nested JWT, and RFC 7519 section 5.2 says `cty`
    must not be set in that case (a strict verifier would parse the plaintext
    as a nested JWT). OID4VP 1.0 section 8.3 does not use it either. The engine
    does not validate `cty` (its header checks cover `alg`, `enc` and `kid`), so
    it accepts a `response_jwe` with or without it.
- For mdoc, the session-transcript thumbprint is computed by the client from
  `response_encryption.jwk`, the one source of the verifier key. The engine
  still sends `verifier_jwk_thumbprint` in `sign_presentation` for
  compatibility; a client must not rely on it when it disagrees with the
  thumbprint computed from `response_encryption.jwk`.
- The engine POSTs `response=<jwe>` (form-urlencoded, nothing else) to the
  validated `response_uri` and relays the verifier's `redirect_uri`.
- The engine cannot decrypt the JWE and never falls back to building it. It
  accepts a `response_jwe` only when all of these hold, and otherwise fails the
  flow with `SIGN_ERROR` and posts `access_denied` (with the same generic
  description every refusal carries, nothing about the cause) to the verifier:
  it is non-empty and at most 4 MiB; it has five base64url segments, none empty
  except the encrypted key of a direct `ECDH-ES` agreement; the protected header
  names the requested `alg` and `enc`, and the JWK's `kid` when it has one; the
  `sign_response` carries no `vp_token`. The same refusal applies when the
  engine cannot resolve a usable public verifier key or algorithms: it then
  sends no `sign_request` at all. "Usable" includes that the key suits the
  `alg`: `ECDH-ES`, `ECDH-ES+A128KW` and `ECDH-ES+A256KW` need an EC key on
  P-256, P-384 or P-521; `RSA-OAEP` and `RSA-OAEP-256` need an RSA key of at
  least 2048 bits; `enc` must be one of `A128GCM`, `A256GCM`, `A128CBC-HS256`
  or `A256CBC-HS512`. Any other pairing is refused the same way. A client that
  still answers with a plain `vp_token` is refused, never encrypted for.
- When the verifier answers that `access_denied` POST with a `redirect_uri`, the
  `SIGN_ERROR` flow error carries it as `details.redirect_uri` (the same detail
  the decline and no-matching-credential errors carry); without one, there are
  no details. Nothing else the verifier sent is passed on.
- Sign refusals are not distinguished yet. `SignResponseMessage` has no `error`
  or `error_code` field in this change, so a correlated reply that carries only
  an error is returned by `Session.RequestSign` as an empty reply: for
  `direct_post.jwt` it has no `response_jwe` and takes the encryption-failure
  path above (`access_denied` to the verifier, `SIGN_ERROR` to the client). A
  separate sign-refusal path needs those fields and a handler for them, which
  is the work of the sign-refusal change (feat/engine-sign-refusal).
- Plain `direct_post` and query/fragment modes are unchanged and the engine
  sees the `vp_token` (and still builds the DCQL object from the client's
  newline-separated tokens): the verifier asked for cleartext. DC API flows run
  in the client and never reach the engine.

## Transports

The legacy WebSocket protocol ([websocket-protocol-spec.md](websocket-protocol-spec.md))
and WMP carry the same fields. The WMP adapter copies `SignRequestParams` into
go-wmp's `openid4x.SignSubFlowParams` field by field, so `response_encryption`
and `state` must be added there, in the go-wmp `openid4x` profile and in the
WMP spec (extension registry and extension rules); a field missing from that
copy is silently dropped. The sign result is decoded from JSON as is, so
`response_jwe` needs no copy.

## Residuals

The engine still sees proof JWTs (holder public key), the verifier request, DPoP traffic, timing and sizes.
