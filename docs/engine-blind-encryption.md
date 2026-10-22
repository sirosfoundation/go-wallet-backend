# Engine-blind encryption

Status: draft. The presentation half is implemented by
https://github.com/sirosfoundation/go-wallet-backend/pull/471. The issuance half
below is the agreed contract and lands with
https://github.com/sirosfoundation/go-wallet-backend/pull/469; it is not yet
implemented in the engine.

The engine relays ciphertext and never sees credential contents, the
`org.siros.secret_seed`, or a `vp_token`. It still sees metadata: which issuer
or verifier, the public verifier request, timing and sizes. Every key used for
this lives in the client (wallet-frontend, Kotlin SDK, Swift SDK). The change
is made in the engine and the clients together; there is no fallback for
clients that predate it.

## Why

Before this change the engine generated the OID4VCI response-encryption key and
decrypted the issuer's JWE itself, and it built and encrypted the OID4VP
`direct_post.jwt` response. So the engine process, and any TLS terminator in
front of it, saw every issued credential, every presentation and every
delivered seed in clear. Seed delivery (privatedata-spec section 5A) requires
an encrypted issuer response, which made that exposure unavoidable.

## Threat model

The engine passes the wallet's response-encryption key to the issuer and the
verifier's key to the wallet, so a compromised engine can substitute either
one. For issuance and for SD-JWT presentations nothing detects the
substitution. For mdoc, OID4VP Annex B.2.6.2 makes it detectable, because the
verifier key's thumbprint is bound into the session transcript, but only after
the engine has already seen the plaintext. The model is therefore
honest-but-curious: the engine is trusted to relay the right keys but not to
read what it relays (OID4VCI section 13.4 covers this setup). It is not a
defence against an actively malicious engine.

## What the engine still needs

- Issuance: only `transaction_id` and `interval` from the response (to poll a
  deferred credential). The client supplies them.
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
   response encryption or advertises `org.siros.secret_seed`.
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
   `{ transaction_id?, interval? }` (or `error`).
6. If a `transaction_id` came back the engine polls the deferred endpoint; each
   answer goes through step 4 again with `deferred: true`. The client keeps its
   key for the whole flow.
7. `flow_complete.credentials[i]` keeps `format`, `vct` and `type_metadata` but
   has no `credential` value; top-level `credential_response_encrypted: true`
   marks it. The client fills entry i from the i-th decrypted credential; a
   count mismatch is an error. For an encrypted response `flow_complete` carries
   no `credential_metadata`. For a plain response the engine may relay only the
   display-only members (`display`, `claims`); extension members such as
   `org.siros.secret_seed` are never relayed from a plain response (the engine
   drops them, and a plain response carrying a seed fails the issuance). Clients
   ignore extension members arriving in `flow_complete`.
8. The client sends the `notification_id` itself in `credential_notification`;
   the engine's notification context holds an empty id, which already matches
   any.
9. Seed validation, size and depth caps, "a seed needs an encrypted response and
   a notification_id", strip-before-merge and the `SHA256(seed) == ssc` check
   are wallet-side. The engine keeps only the rule that an advertised
   `org.siros.secret_seed` makes `required` true.
10. If the issuer offers no response encryption, the response is plaintext and
    the engine sees it; that is the issuer's choice.

## Presentation (OID4VP, `response_mode=direct_post.jwt`)

- `sign_presentation` carries `verified_request`
  (`client_id`, `client_id_scheme`, `response_mode`, `response_uri`, `signed`,
  `signature_verification`, `client_metadata`). The client takes the JARM
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
  sends no `sign_request` at all. A client that still answers with a plain
  `vp_token` is refused, never encrypted for.
- A `sign_response` that carries `error` or `error_code` (a sign refusal)
  carries no `response_jwe`; the refusal path is unchanged and is not an
  encryption failure.
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

The engine still sees proof JWTs (holder public key; the `psc` commitment is
hiding by design), the verifier request, DPoP traffic, timing and sizes.
