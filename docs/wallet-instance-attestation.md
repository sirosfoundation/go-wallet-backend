# Wallet Instance Attestation (WIA)

go-wallet-backend can act as a **wallet provider**: it issues Wallet Instance Attestations (WIAs) that let this wallet authenticate to credential issuers per [draft-ietf-oauth-attestation-based-client-auth](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html), without the issuer pre-registering an OAuth `client_id` for every wallet deployment.

See `docs/CONFIGURATION.md`'s `wallet_provider.wia.*` section for the full field reference. This document explains the moving parts and the two supported identity formats.

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /wallet-provider/wia/challenge` | Issues a single-use nonce. The caller signs it into a PoP JWT to prove possession of the attestation key before a WIA is issued for it. |
| `POST /wallet-provider/wia/generate` | Verifies the challenge PoP, then issues a WIA (`wallet_instance_attestation`) bound to the caller's key. |
| `GET /.well-known/jwks.json` | Serves the wallet provider's own signing public key (`RegisterWalletProviderJWKSRoute`, `internal/service/wallet_provider_jwks.go`). Only registered when a wallet-provider signing key is configured. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata pointing at the JWKS above (`issuer` + `jwks_uri`). Only registered in `ietf` mode (see below) with `wallet_provider.wia.issuer` (or `wallet_provider_uri` as fallback) set. |
| `GET /wallet-provider/status-list` | Always-empty (never revoked) Token Status List, for interop completeness only — no WIA/KA this wallet provider issues actually references it (`RegisterWalletProviderStatusListRoute`, `internal/service/wallet_provider_statuslist.go`). |

## Two identity formats: x5c vs. `iss`-based

Controlled by `wallet_provider.wia.mode`:

- **`etsi` (default)** — the EUDI ARF v3.0 / EC TS03 v1.5.2 / ETSI TS 119 472-3 model. The WIA's JOSE header carries the wallet provider's `x5c` certificate chain; relying parties verify it against the Trusted List for Wallet Providers and treat the embedded certificate as the authoritative key. No `iss` or `kid` is set. This is the only mode with a defined trust path under the current EUDI/ARF/ETSI specs.
- **`ietf`** — the generic IETF `draft-ietf-oauth-attestation-based-client-auth` model, with no ARF/ETSI counterpart. No certificate chain is attached — this is the *only* way to actually exercise `iss`/JWKS-based trust when a certificate happens to be configured, since `etsi` mode ignores `iss` in favor of the cert. Requires `wallet_provider.wia.issuer` to be set. Relying parties must then resolve the signing key themselves from `<issuer>/.well-known/jwks.json` (or the RFC 8414 document above), matched by the WIA's JOSE `kid` header — which is always set to `"wallet-provider"` in this mode, the same `KeyID` the JWKS route publishes.

The IETF draft leaves key-resolution/trust-establishment mechanisms explicitly out of scope (§9.8) — `iss` + JWKS + `kid` is one of the draft's own suggested strategies, not a SIROS invention, but relying parties differ in *how* they discover the JWKS from `iss`. That's why both a bare `.well-known/jwks.json` and a wrapping RFC 8414 document are published: some discovery chains (e.g. SD-JWT VC §5.3-style resolvers) look for a metadata document with a `jwks_uri` field and never try a bare JWKS path directly.

## `iss` vs. `wallet_provider_uri` — two different audiences

These are easy to conflate but serve different JWTs:

- **`wallet_provider.wia.issuer`** → the WIA's own `iss` claim, and (via `WalletProviderService.Issuer()`) the `issuer` field in the RFC 8414 metadata above. Identifies *this wallet provider* to whoever receives a WIA it issued.
- **`wallet_provider.wia.wallet_provider_uri`** → the expected `aud` on the **WIA-request PoP** — the short-lived proof-of-possession JWT a caller sends to *this service's own* `/wallet-provider/wia/generate` endpoint when requesting a WIA. A completely different JWT, audience, and purpose from the WIA itself.

In this deployment's config both happen to be the same URL (the wallet-proxy's public address), but that's a deployment choice, not a requirement — `Issuer()` and the PoP-audience check are independent code paths.

## Client-side convention this depends on

Nothing here constrains what OAuth `client_id` the wallet ultimately uses with the credential issuer — but whatever value it is, it becomes the WIA's `sub` claim (see `GenerateWIA` in `internal/service/wia.go`), and the issuer's PAR handler will reject the attestation if `sub` doesn't match the `client_id` it resolves for that request. For unregistered clients, this backend's own AS module (`internal/engine/oid4vci.go`) defaults `client_id` to the caller's `redirect_uri` (OID4VCI §7.1 convention) — client integrations (e.g. wallet-frontend) must pass that same value as the WIA's `client_id`, not, say, the credential issuer's URL.

## Related

- `docs/client-id-strategy.md` — the broader cross-repo plan this fits into (Phase 4a).
- SUNET/vc: `docs/TRUST_AND_IDENTITY.md`'s "Wallet Attestation" section — issuer-side verification and trust evaluation.
- wallet-frontend: `docs/WALLET_ATTESTATION.md` — client-side generation and the client_id/aud pitfalls hit integrating against this backend.
- developers.siros.org: [Wallet Attestation](https://developers.siros.org/docs/sirosid/trust/wallet-attestation) and the attestation-based authentication how-to guide.
