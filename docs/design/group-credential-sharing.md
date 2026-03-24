# Group Credential Sharing via MLS

**Status**: Design / Investigation  
**Created**: 2026-03-06  
**Author**: leifj  

## 1. Problem Statement

Individual wallets holding credentials in isolation cannot address several real-world scenarios:

- **Family credentials**: A family insurance card usable by any family member's wallet
- **Organizational delegation**: An employee badge credential usable from multiple devices or shared across a team
- **Device continuity**: A user's credentials accessible from both phone and laptop wallets without re-issuance
- **Guardian/custodial**: A parent holding credentials on behalf of a minor, transferable when the minor gets their own wallet

The current architecture stores all credentials in a single per-user `WalletStateContainer` encrypted under a PRF-derived main key. There is no mechanism for multiple wallets to share access to the same credential material.

## 2. Design Goals

1. **Shared credential groups**: Users can maintain multiple groups of credentials, each stored separately
2. **MLS-based key agreement**: Each credential group is tied to an MLS group providing group key management
3. **Cross-wallet sharing**: Credential groups are shared between wallets (subject to policy)
4. **Delegated presentation/issuance**: All group members can present and accept issuance for group credentials (subject to policy)
5. **Perfect forward secrecy on ejection**: When a wallet is removed from a group, it loses access to future credential material via MLS epoch advancement

## 3. Architecture

### 3.1 Key Hierarchy

The existing wallet already supports **multiple FIDO tokens** per account. Each token has its own PRF output, but all PRF keys independently encapsulate (wrap) the **same main key**. The `prfKeys` array in `EncryptedContainer` holds one entry per registered FIDO token, each containing that token's PRF salt, HKDF parameters, and an ECDH-based encapsulation of the main key.

```
FIDO Token A (PRF-A)  FIDO Token B (PRF-B)  Password
         │                     │                │
    HKDF(PRF-A)           HKDF(PRF-B)       PBKDF2
         │                     │                │
    PRF Key A             PRF Key B        Password Key
         │                     │                │
         └────── ECDH-ES ──────┴──── ECDH-ES ──┘
                     │
                     ▼
              Personal Main Key (AES-256-GCM)
                     │
                     ├──► Personal WalletStateContainer (JWE)
                     │     (credentials, settings, MLS identity key)
                     │
                     ▼
              MLS Identity Key (ECDSA P-256, stored in personal container)
                     │
                     ├──► MLS Group A ──► Epoch Key A ──► GroupStateContainer A
                     │     (family credentials)
                     │
                     ├──► MLS Group B ──► Epoch Key B ──► GroupStateContainer B
                     │     (org department credentials)
                     │
                     └──► MLS Group C ──► Epoch Key C ──► GroupStateContainer C
                           (multi-device sync)
```

**Key point**: All FIDO tokens registered to the same account unlock the **same** personal main key, which decrypts the **same** `WalletStateContainer` containing the **same** MLS identity key. From MLS's perspective, any of the user's FIDO tokens opens the same wallet with the same group memberships. The multi-PRF layer is transparent to MLS.

### 3.1.1 Multiple FIDO Tokens and Group Sharing

Multiple FIDO tokens interact with group credential sharing at several levels:

#### Recovery

If a FIDO token is lost, any other registered token (or password) can still open the wallet and access all MLS group memberships. This is the primary motivation for registering multiple tokens. The `addPrf()` function wraps the existing main key under a fresh PRF-derived key, so adding a recovery token does not re-key the wallet.

#### Same-User Multi-Device

A user with FIDO tokens on phone and laptop authenticates from either device to the **same** wallet account. The server stores one `privateData` blob; each authentication unlocks it via different PRF outputs. This solves the "device continuity" case from §1 **without MLS** — the user already has one wallet with one state container accessible from multiple devices.

MLS group sharing (§5) is needed for the harder problem: **different wallet accounts** (different users, or same user with intentionally separate wallet identities) sharing credentials.

#### FIDO-Bound Signing Keys

Each FIDO token may host **device-bound signing keys** that are non-exportable (see §4.4). These keys differ from the software signing keys stored in `WalletStateContainer`:

| Key type | Where stored | Unlocked by | Shareable? |
|----------|-------------|-------------|------------|
| PRF-derived main key | Server (encrypted) | Any registered FIDO token or password | N/A (encryption key, not signing key) |
| Software signing keys | Inside `WalletStateContainer` (`wrappedPrivateKey`) | Any registered FIDO token → main key → decrypt | Yes (group sharing Option A) |
| Hardware-bound signing keys (ARKG) | On specific FIDO token (`externalPrivateKey`) | Only that token's authenticator via `previewSign` extension | **No** |

A credential bound to a hardware key on FIDO Token A **cannot be presented from FIDO Token B**, even though both tokens belong to the same wallet account. The wallet must track which credentials are tied to which authenticator and only attempt presentation when the correct hardware token is present.

This has implications for MLS groups:
- **Software-keyed credentials** stored in a group state container can be presented by any group member — the private key is in the shared state
- **Hardware-keyed credentials** cannot enter a group state container — the private key cannot be extracted or shared
- The SPOCP policy engine (§7.3) should encode: `(share (key_type software) (format *))` permits sharing; `(share (key_type hardware) ...)` does not match

#### Token Lifecycle in Group Membership

When a FIDO token is **removed** from a wallet (`deletePrf`), the wallet re-encrypts the main key under the remaining tokens only. But MLS group state is already protected by MLS epoch keys, not the wallet's main key. Removing a FIDO token from a wallet account does **not** require MLS group epoch advancement — the MLS identity key is unchanged, only one unlock path to it was revoked.

When a wallet account is **removed from an MLS group**, all FIDO tokens for that account lose access simultaneously (via MLS epoch advancement). There is no per-token granularity at the MLS layer.

### 3.2 Group Epoch Key Derivation

```
MLS epoch_secret (from TreeKEM)
         │
         ▼
HKDF-Expand(epoch_secret, "group-credential-encryption", 32)
         │
         ▼
AES-256-GCM key ──► Encrypts GroupWalletState as JWE
```

When MLS advances an epoch (member add/remove/update), a new encryption key is derived. The group state is re-encrypted under the new key. Removed members cannot derive the new epoch secret.

### 3.3 Data Model

```typescript
// Personal wallet state gains a new field
type WalletState = {
  // ... existing fields ...
  mlsIdentityKey: {
    publicKey: JWK;
    privateKey: JWK;       // ECDSA P-256 (MLS credential)
  };
  groupMemberships: GroupMembership[];
}

type GroupMembership = {
  groupId: string;
  role: GroupRole;
  joinedEpoch: number;
  mlsGroupState: Uint8Array;  // Serialized MLS group state for this member
}

// Per-group encrypted container (stored on backend per group)
type GroupStateContainer = {
  groupId: string;
  epoch: number;
  jwe: string;                // Encrypted GroupWalletState
}

type GroupWalletState = {
  credentials: GroupCredential[];
  keypairs: CredentialKeyPair[];     // Shared signing keys
  members: GroupMember[];
  policy: GroupPolicy;
  spocpRules: string[];              // SPOCP policy rules for this group
  events: GroupSessionEvent[];       // Event-sourced history
  lastEventHash: string;
}

type GroupCredential = {
  credentialId: number;
  data: string;                      // The VC / mDL
  format: string;
  kid: string;                       // References shared keypair
  keyBinding: KeyBindingType;        // Shareability constraint
  privacyLevel: PrivacyLevel;        // Unlinkability classification
  metadata: {
    issuer: string;
    subject: string;                 // Group DID or individual
    issuedAt: number;
  };
}

type KeyBindingType = 'software' | 'hardware' | 'external_hsm';
// software:      wrappedPrivateKey in CredentialKeyPair — exportable, shareable
// hardware:      externalPrivateKey (ARKG/WebAuthn sign extension) — NOT shareable
// external_hsm:  HSM-backed (agent keys) — shareable within HSM boundary
// Detection: 'wrappedPrivateKey' in keypair → software; 'externalPrivateKey' in keypair → hardware

type PrivacyLevel = 'high' | 'medium' | 'low';
// high:   Longfellow ZK anonymous credentials (selective disclosure, fully unlinkable)
//         Implemented via zk-cred-longfellow WASM component in the frontend
// medium: Batch-issued (instances.length > 1), each single-use, unlinkable across presentations
// low:    Single instance, reused, linkable

type GroupMember = {
  walletId: string;                  // MLS leaf node identity
  displayName: string;
  role: GroupRole;
  joinedEpoch: number;
  permissions: GroupPermissions;
}

type GroupRole = 'owner' | 'admin' | 'member' | 'reader';

type GroupPolicy = {
  presentation: 'any_member' | 'quorum' | 'owner_only';
  issuance: 'any_member' | 'owner_only';
  addMember: 'admin_or_above' | 'owner_only';
  removeMember: 'admin_or_above' | 'owner_only';
  rotateOnMemberRemoval: boolean;
  minMembers: number;
  quorumSize?: number;
  // SPOCP policy rules (overrides for this group, merged with tenant defaults)
  sharingRules?: string[];           // e.g. "(share (key_type software) (privacy *) (format *))"
  signingRules?: string[];           // e.g. "(sign (action *) (key_type software))"
  presentationRules?: string[];      // e.g. "(present (role member) (credential_type *))"
}

type GroupPermissions = {
  canPresent: boolean;
  canAcceptIssuance: boolean;
  canAddCredential: boolean;
  canRemoveCredential: boolean;
}
```

### 3.4 Backend API

New endpoints for group management (server sees only opaque encrypted blobs):

```
POST   /groups                              Create group
GET    /groups/{groupId}/state              Get group encrypted state
PUT    /groups/{groupId}/state              Update group encrypted state
DELETE /groups/{groupId}                    Delete group
```

MLS message relay endpoints are defined in §8.2 (MLS Transport Model). All MLS endpoints use `Content-Type: application/mls-message` and the engine treats payloads as opaque bytes.

## 4. Private Key Sharing Strategy

### 4.1 Option A: Direct Key Sharing (Phase 1)

The credential's ECDSA private key (JWK) is stored in the `GroupWalletState`. Any member who can decrypt the group state can sign presentations.

**Pros**: Simple, works with existing VC/mDL ecosystems, no changes to verifier  
**Cons**: A member who exfiltrates the key before ejection retains signing capability until the credential is revoked/rotated

**Mitigation**: `rotateOnMemberRemoval: true` policy triggers re-issuance with new keypairs when a member is ejected. Old credentials are revoked.

### 4.2 Option B: Threshold Signatures / MPC (Future)

The private key is split into shares; presentation requires $t$-of-$n$ cooperation.

**Pros**: No single wallet ever holds the full key  
**Cons**: Interactive protocol during presentation, ecosystem support lacking

### 4.3 Option C: Delegation Chains (Future)

The group holds a root credential. Each member gets a derived credential via delegation attestation or VC chaining.

**Pros**: Closest to real organizational credentials, per-member revocation  
**Cons**: Requires issuer support for delegation, new credential formats

### 4.4 Hardware-Bound Key Constraints

Some credentials are bound to hardware-protected keys (e.g., Secure Enclave, StrongBox, TPM) that **cannot be exported or shared by design**. These include:

- **Device-bound mDL keys**: ISO 18013-5 `DeviceAuth` requires signing with a key locked to the device's secure element
- **WSCD-bound PID keys**: eIDAS2 QSCD/WSCD requirements mandate that high-assurance PID private keys never leave the hardware
- **FIDO2/passkey-derived keys**: Keys generated via WebAuthn with `authenticatorAttachment: "platform"` are non-exportable by the CTAP2 spec
- **Key-attested credentials**: When the issuer requires `key_attestation` proof type, the attestation binds the credential to a specific key that was attested as hardware-protected

These credentials are fundamentally **not shareable** via any of Options A–C above. The group sharing model must detect and respect this constraint rather than silently failing at presentation time.

**Detection strategies:**
1. **Key pair type discrimination** (concrete, from PR #1025): `CredentialKeyPair` is a union — if `'externalPrivateKey' in keypair` it is hardware-bound; if `'wrappedPrivateKey' in keypair` it is software-managed. This is a **compile-time checkable** binary test.
2. **Proof type metadata**: If `proof_types_supported` requires `key_attestation`, the credential likely demands hardware binding
3. **Key storage flag**: The wallet tracks where each key is stored (`hardware` / `software` / `external`) in `CredentialKeyPair`
4. **Credential policy annotation**: Issuers annotate shareability in credential metadata (future standard)

### Recommendation

Start with **Option A** for Phase 1. MLS forward secrecy + credential rotation on ejection provides acceptable security. Plan upgrade paths to Option C (delegation) for high-assurance use cases.

Hardware-bound credentials must be explicitly excluded from group sharing. Policy enforcement should use a SPOCP engine (see §7.3) to make shareability decisions based on key type, credential format, and issuer requirements.

### 4.5 ARKG and Hardware-Bound Batch Credentials

PR [wwWallet/wallet-frontend#1025](https://github.com/wwWallet/wallet-frontend/pull/1025) introduces **ARKG (Asynchronous Remote Key Generation)** via the WebAuthn `previewSign` extension (v4). This is the concrete implementation of hardware-bound credential keys and fundamentally changes the key management model.

#### 4.5.1 ARKG Architecture

Instead of generating individual keys, the authenticator generates an **ARKG seed keypair**. The wallet stores the public seed and can derive arbitrarily many child public keys **without contacting the authenticator**. When a signature is needed, the authenticator reconstructs the corresponding private key from the seed + key handle + ARKG delegation parameters.

```
┌──────────────────┐
│  FIDO Authenticator  │
│  (YubiKey 5.8+)  │
│                  │
│  ARKG Seed ──────┼──► publicSeed (exported to wallet)
│    (private)     │       ├── pkBl (blinding key)
│                  │       └── pkKem (KEM key)
│  KeyHandle ──────┼──► keyHandle (exported to wallet)
│                  │
│  DerivePrivate() │◄── kh (ARKG delegation handle)
│                  │◄── ctx (context)
│                  │──► signature
└──────────────────┘

       Wallet (client-side, no authenticator needed):
       
       derivePublicKey(publicSeed, ikm, ctx) → childPublicKey, arkgKeyHandle
       
       Authenticator (signing time only):
       
       previewSign.signByCredential[credentialId] = {
           keyHandle,
           tbs: sha256(data),
           additionalArgs: encodeArkgSignArgs(algorithm, { kh, ctx })
       }
```

**Key insight**: Public key derivation is **pure client-side math** — it can be performed offline, in batch, without any authenticator interaction. Only **signing** requires the physical authenticator. This enables efficient batch credential issuance with hardware-bound keys.

#### 4.5.2 Wallet State Types (Schema V4/V5)

PR #1025 introduces two new schema versions:

```typescript
// Schema V4: New credential key pair union
type CredentialKeyPairWithCleartextPrivateKey = {
    // ... existing fields
    wrappedPrivateKey: WrappedPrivateKey,  // software key, encrypted in wallet state
}
type CredentialKeyPairWithExternalPrivateKey = {
    // ... common fields (alg, publicKey, did, kid)
    externalPrivateKey: WebauthnSignKeyRef,  // hardware key, lives on authenticator
}
type CredentialKeyPair = CredentialKeyPairWithCleartextPrivateKey
                       | CredentialKeyPairWithExternalPrivateKey;

// Schema V5: Refined key references
type WebauthnSignPrivateKeyArkg = {
    credentialId: Uint8Array,   // which authenticator
    keyHandle: Uint8Array,      // reference to seed key on authenticator
    algorithm: COSEAlgorithmIdentifier,
    additionalArgs: {
        kh: Uint8Array,         // ARKG delegation handle
        ctx: Uint8Array,        // derivation context
    },
}

// ARKG public seed stored in wallet state
type WebauthnSignArkgPublicSeed = {
    credentialId: Uint8Array,
    publicSeed: ParsedCOSEKeyArkgPubSeed,
    keyHandle: Uint8Array,
    derivedKeyAlgorithm: COSEAlgorithmIdentifier,
}

// Wallet state gains arkgSeeds array
type WalletState = {
    // ... existing fields
    keypairs: { kid: string, keypair: CredentialKeyPair }[],
    arkgSeeds: MaybeNamed<WebauthnSignArkgPublicSeed>[],
}
```

#### 4.5.3 Privacy Level Classification

PR #1025 introduces a three-level privacy classification for credentials, shown in UI as `CredentialStatusIndicatorsRibbon`:

| Privacy Level | Condition | Meaning |
|--------------|-----------|---------|
| **High** | Longfellow ZK proof | Selective disclosure via ZK anonymous credentials from ECDSA (fully unlinkable) |
| **Medium** | `instances.length > 1` | Batch-issued — each instance single-use, unlinkable across presentations |
| **Low** | Single instance | Reused across presentations, linkable |

> **Note**: PR #1025's Settings UI has a "High privacy" hardware key slot with `alg: null` and a disabled "Not yet supported" button (originally referencing `COSE_ALG_SPLIT_BBS`). Our plan is to replace the BBS+ approach with [zk-cred-longfellow](https://github.com/abetterinternet/zk-cred-longfellow) — a Rust/WASM implementation of "Anonymous Credentials from ECDSA" ([draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)). Because Longfellow operates on standard ECDSA keys rather than requiring a separate BBS+ key type, the high-privacy path may not need a distinct COSE algorithm or hardware key slot at all — it can produce unlinkable ZK proofs from existing ECDSA credential keys.

And a binary **type** classification:

| Type | Condition | Meaning |
|------|-----------|---------|
| `hw-bound` | `'externalPrivateKey' in keypair` | Key lives on hardware authenticator |
| `synced` | `'wrappedPrivateKey' in keypair` | Key encrypted in wallet state (software) |

These two dimensions combine into a shareability matrix:

| Privacy × Type | hw-bound | synced (software) |
|----------------|----------|-------------------|
| **High** | Not shareable; best privacy | **Potentially shareable**: Longfellow operates on standard ECDSA keys — if the credential's ECDSA private key is in the group state (`wrappedPrivateKey`), any member can produce ZK proofs from it. The ZK proof itself is unlinkable. |
| **Medium** (batch) | Not shareable; but each group member could independently derive+issue from their own ARKG seed | **Shareable**: distribute different batch instances to different group members for per-member unlinkability |
| **Low** (single) | Not shareable | **Shareable**: all group members use same credential (linkable) |

#### 4.5.4 Implications for Group Credential Sharing

**1. Shareability is now binary-testable:**
```typescript
function isShareable(keypair: CredentialKeyPair): boolean {
    return 'wrappedPrivateKey' in keypair;
}
```
There is no ambiguity, no heuristic, no reliance on transport hints. This is the detection mechanism for §4.4.

**2. ARKG strictly increases the set of non-shareable credentials.** Previously all credential keypairs were software-managed (`wrappedPrivateKey`). PR #1025 adds a new category (`externalPrivateKey`) where the private key never leaves the authenticator. Any credential issued against an ARKG-derived public key is permanently bound to the physical device.

**3. ARKG public derivation is shareable, but useless for group sharing.** A group member could share their ARKG public seed, and another member could derive a child public key from it. But the resulting credential would **still be bound to the original member's authenticator** — only that authenticator can sign with the derived key. Sharing the seed creates no delegation of signing capability.

**4. Batch instance distribution in groups.** For medium-privacy software-keyed credentials (batch-issued with `wrappedPrivateKey`), a group could distribute different instances to different members. Each instance has its own keypair and `sigCount`. This provides per-member unlinkability while sharing the same credential type. The `getLeastUsedCredentialInstance()` helper already selects instances by usage count.

**5. Hardware-bound credentials need per-member re-issuance.** If a group requires hardware-bound credentials for all members, each member must independently:
   - Register their own ARKG seed (via their own physical authenticator)
   - Derive public keys from their seed
   - Request credential issuance to their derived keys
   - The group coordinates issuance but each member holds their own non-shareable credential instance

**6. Schema version conflict.** PR #1025 uses Schema V4 and V5 for the ARKG keypair types. Our group sharing design proposed `GroupStateContainer` as a new schema version. The group sharing migration must be **V6 or later**, building on top of PR #1025's ARKG types.

**7. API changes.** PR #1025 renames keystore methods:
   - `initPrf()` → `initWebauthn()` (also handles ARKG seed generation during account creation)
   - `addPrf()` → `beginAddPrf()` + `finishAddPrf()` (split into two phases)
   - New: `registerWebauthnSignKeypair(alg, executeWebauthn)` for ARKG seed registration
   - `signJwtPresentation()` and `generateOpenid4vciProofs()` now accept a `webauthnSignRetryLoop` callback for interactive authenticator signing
   
Any group sharing code interacting with the keystore must use these updated APIs.

## 5. MLS Integration

### 5.1 Library Options

| Library | Language | Browser Support | Maturity |
|---------|----------|-----------------|----------|
| [OpenMLS](https://openmls.tech/) | Rust/WASM | Via wasm-bindgen | Production-grade, RFC 9420 compliant |
| [mls-ts](https://github.com/nicholasgasior/mls-ts) | TypeScript | Native | Early stage |
| [cisco/mls-rs](https://github.com/nicholasgasior/mls-ts) | Rust/WASM | Via wasm-bindgen | Active development |

**Recommendation**: OpenMLS via WASM. Most mature, well-tested, RFC 9420 compliant.

### 5.2 MLS Credential Binding

Each wallet's MLS leaf node uses its MLS identity key (stored in personal container). The MLS credential type should be `x509` or `basic` with the wallet's identity.

### 5.3 Epoch Lifecycle

```
Create Group:
  Owner generates MLS group → epoch 0 → derives key → encrypts initial GroupWalletState

Add Member:
  Admin creates MLS Add proposal + Commit → epoch N+1
  Welcome message sent to new member via backend
  New member processes Welcome → gets epoch N+1 key → can decrypt GroupWalletState

Remove Member:
  Admin creates MLS Remove proposal + Commit → epoch N+1
  Remaining members process Commit → get new epoch key
  GroupWalletState re-encrypted with new epoch key
  If rotateOnMemberRemoval: trigger re-issuance of all credentials

Update (key rotation):
  Any member creates MLS Update + Commit → epoch N+1
  Periodic key rotation for forward secrecy even without membership changes
```

## 6. Credential Binding & Identity

### 6.1 Who is the Subject?

Two models:

**Group-as-subject**: Credentials are issued to a group DID (e.g., `did:key:z...` of the shared keypair). Any group member can present. The verifier sees the group identity, not individual members.

**Individual-as-subject with group access**: Credentials are issued to an individual but stored in the group. Other members can present using the shared private key, but the credential identifies the original subject. This is the "family card" model.

### 6.2 Group DID

A group could be represented as:
- `did:key` of the shared signing keypair (simple, stateless)
- `did:web` or `did:tdw` pointing to a group DID document (supports key rotation, member listing)

## 7. Security Analysis

### 7.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Ejected member retains cached credentials | Credential rotation on removal + issuer revocation |
| Ejected member retains private key | MLS forward secrecy prevents future access; rotation creates new keys |
| Compromised backend | Server stores only encrypted blobs; no access to keys or credentials |
| Malicious group member | Policy-based access control; audit log in event history |
| MLS state desync | Event-sourced merge strategy (existing `mergeEventHistories`) |
| Offline member misses epoch update | MLS Welcome-style catch-up; backend stores committed epochs |

### 7.2 Limitations

- **No retroactive secrecy**: A member present during epoch $e$ could have recorded decrypted material. MLS only provides post-compromise security.
- **Offline presentation after ejection**: A member who cached credentials offline can present until the credential is revoked by the issuer.
- **mDL incompatibility**: ISO 18013-5 device binding assumes a single device. Sharing mDL across wallets is architecturally incompatible unless using delegation (Option C).

### 7.3 SPOCP-Based Sharing & Signing Policy

The decision "can this credential be shared?" and "which key may sign this presentation?" should not be hardcoded logic scattered across flow handlers. Instead, these policies should be encapsulated in a **SPOCP engine** ([go-spocp](https://github.com/sirosfoundation/go-spocp)) — a generalized authorization engine based on restricted S-expressions that supports subsumption-based policy evaluation.

#### Why SPOCP

SPOCP's subsumption model (`query ≤ rule`) is a natural fit for hierarchical policy decisions:

- A rule `(share (key_type software) (format *))` permits sharing any credential whose key is software-managed
- A query `(share (key_type hardware) (format mdoc))` would **not** match — hardware-bound keys are not subsumed by the rule
- A rule `(share (key_type software) (privacy medium) (format *))` restricts sharing to batch-issued software credentials
- Wildcard/range support (`*`, prefix matching) handles open-ended credential formats without enumerating each one

This is more expressive than simple role-based checks and avoids the boolean flag explosion that `GroupPolicy` would otherwise require.

#### Policy Evaluation Points

```
┌──────────────────────────────────────────────────────────┐
│                    SPOCP Policy Engine                    │
│                                                          │
│  Rules loaded from: tenant config / group policy / issuer│
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ (share (key_type software) (format sd-jwt-vc))      │ │
│  │ (share (key_type software) (format mdoc))           │ │
│  │ (share (key_type software) (privacy medium))        │ │
│  │ (sign  (action sign_presentation) (key_type *))     │ │
│  │ (sign  (action generate_proof)    (key_type hw))    │ │
│  │ (present (role member) (credential_type *))         │ │
│  │ (present (role reader))                    ← DENY   │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
         ▲                    ▲                    ▲
         │                    │                    │
   Add credential       Sign request        Present credential
   to group?            (which key?)         (who may present?)
```

**Evaluation points in the engine:**

| Decision | Query example | When |
|----------|--------------|------|
| Can this credential be shared into a group? | `(share (key_type software) (privacy medium) (format sd-jwt-vc) (issuer did:web:issuer.example))` | User moves credential to group state |
| Which key type is required for this signature? | `(sign (action generate_proof) (format mdoc) (issuer did:web:issuer.example))` | Engine's `RequestSign` before delegating to client |
| Can this group member present this credential? | `(present (role member) (credential_type org-pid))` | Before initiating OID4VP response |
| Can a one-shot proxy presentation be issued? | `(proxy (credential_type employee-badge) (recipient did:key:z...))` | One-shot sharing request (§10) |

#### Integration with go-wallet-backend Engine

The `feature/v2-api` engine currently has two `SignAction` values (`generate_proof`, `sign_presentation`) that are sent to the client without any server-side key-type gating. A SPOCP policy layer would sit between the flow handler and `RequestSign`:

```go
import "github.com/sirosfoundation/go-spocp"

// SigningPolicy evaluates whether a signing operation is permitted
// and determines key requirements.
type SigningPolicy struct {
    engine *spocp.Engine
}

// EvaluateSign checks if the requested sign action is permitted for the
// given credential and returns the required key type constraint.
func (sp *SigningPolicy) EvaluateSign(action SignAction, credFormat string, 
    keyType string, issuer string) (bool, error) {
    query := fmt.Sprintf("(sign (action %s) (format %s) (key_type %s) (issuer %s))",
        action, credFormat, keyType, issuer)
    return sp.engine.Query(query)
}

// EvaluateShare checks if a credential can be moved into a group.
func (sp *SigningPolicy) EvaluateShare(keyType string, credFormat string, 
    issuer string, privacyLevel string) (bool, error) {
    query := fmt.Sprintf("(share (key_type %s) (format %s) (issuer %s) (privacy %s))",
        keyType, credFormat, issuer, privacyLevel)
    return sp.engine.Query(query)
}
```

The `BaseHandler.RequestSign` would become policy-aware:

```go
func (h *BaseHandler) RequestSign(ctx context.Context, action SignAction, 
    params SignRequestParams) (*SignResponseMessage, error) {
    // Policy check: is this sign action permitted with the credential's key type?
    if h.SigningPolicy != nil {
        allowed, err := h.SigningPolicy.EvaluateSign(action, params.ProofType, 
            params.KeyType, params.Issuer)
        if err != nil {
            return nil, fmt.Errorf("policy evaluation failed: %w", err)
        }
        if !allowed {
            return nil, fmt.Errorf("signing policy denied: action=%s key_type=%s", 
                action, params.KeyType)
        }
    }
    return h.Flow.Session.RequestSign(ctx, h.Flow.ID, action, params)
}
```

#### Relationship to AuthZEN Trust Evaluation

SPOCP handles **local policy** (what keys/credentials/actions are permitted within this wallet deployment), while AuthZEN handles **external trust** (is this issuer/verifier trusted?). They are complementary:

| Concern | Engine | Protocol |
|---------|--------|----------|
| "Is this issuer trusted?" | AuthZEN PDP (`TrustService`) | AuthZEN evaluation API |
| "Can this key sign this proof?" | SPOCP (`SigningPolicy`) | Local s-expression evaluation |
| "Can this credential be shared?" | SPOCP (`SigningPolicy`) | Local s-expression evaluation |
| "Is this verifier authorized to request this credential?" | AuthZEN PDP | AuthZEN evaluation API |

#### Policy Sources

Rules can be loaded from multiple sources, merged into a single SPOCP engine per tenant:

1. **Tenant configuration**: Default sharing/signing policies per deployment
2. **Group policy**: Per-group overrides (stored in `GroupWalletState.policy`)
3. **Issuer metadata**: Issuer-specified constraints (e.g., "this credential must use hardware keys")
4. **Credential metadata**: Per-credential annotations from issuance

## 8. Engine Integration & Messaging

### 8.1 Engine as MLS Message Relay

The go-wallet-backend engine already provides:
- **WebSocket sessions** with `Session.Send()` for server-initiated push
- **`TypePush` / `PushMessage`** for server→client notifications
- **`Manager.GetSessionByUser(userID)`** for targeting specific wallets
- **`SessionStore`** (pluggable to Redis) for horizontal scaling

MLS group sync does not fit the flow model (`FlowHandler` with start→complete lifecycle). Instead, a **GroupRelay** service sits alongside the flow engine.

### 8.2 MLS Transport Model

MLS messages are **never sent wallet-to-wallet**. The engine acts as a **store-and-forward relay**. Ingestion is always REST; delivery is opportunistic WebSocket push + REST polling.

```
Wallet A                         Engine (GroupRelay)              Wallet B
   │                               │                                │
   │  POST /groups/{gid}/mls/commit│                                │
   │  Content-Type:                │                                │
   │    application/mls-message    │                                │
   │ ─────────────────────────────►│                                │
   │                               │── persist to GroupStore        │
   │                               │                                │
   │                               │── lookup group members         │
   │                               │── GetSessionByUser(walletB)    │
   │                               │                                │
   │                               │  PushMessage{                  │
   │                               │    push_type: "mls_commit",    │
   │                               │    group_id: gid,              │
   │                               │    epoch: N+1                  │
   │                               │  }                             │
   │                               │───────────────────────────────►│
   │                               │  (WebSocket, if connected)     │
   │                               │                                │
   │                               │   [Wallet C is offline]        │
   │                               │── queue for offline delivery   │
   │                               │                                │
   │                               │         [Wallet C reconnects]  │
   │                               │                                │
   │                               │ GET /groups/{gid}/mls/commits  │
   │                               │   ?since_epoch=N               │
   │                               │◄───────────────────── Wallet C │
   │                               │────────────────────► Wallet C  │
   │                               │  (all pending commits)         │
```

**Key design decisions:**

1. **REST for ingestion, WebSocket for notification only** — The WebSocket push is a lightweight notification ("new commit available for group X at epoch N+1"). The wallet then fetches the full MLS message via REST if needed, or the push payload can include the commit bytes for small messages. This avoids mixing large binary MLS blobs into the WebSocket flow-control protocol.

2. **Persist-before-push** — The commit is written to `GroupStore` before any push attempt. This ensures durability across engine restarts and correct delivery to offline members.

3. **Idempotent consumption** — Wallets track their last-processed epoch. `GET /groups/{gid}/mls/commits?since_epoch=N` returns all commits after epoch N. Wallets can safely re-fetch without side effects.

4. **Content type** — MLS messages use `Content-Type: application/mls-message` per RFC 9420 §17.1. The engine treats them as opaque bytes — it never decrypts or inspects the MLS ciphertext.

**REST endpoints for MLS relay:**

| Method | Path | Content-Type | Purpose |
|--------|------|-------------|----------|
| POST | `/groups/{gid}/mls/commit` | `application/mls-message` | Submit MLS Commit |
| GET | `/groups/{gid}/mls/commits?since_epoch=N` | — | Fetch pending Commits |
| POST | `/groups/{gid}/mls/proposal` | `application/mls-message` | Submit MLS Proposal |
| GET | `/groups/{gid}/mls/proposals` | — | Fetch pending Proposals |
| POST | `/groups/{gid}/mls/welcome` | `application/mls-message` | Store Welcome for new member |
| GET | `/groups/{gid}/mls/welcome/{member_id}` | — | Retrieve Welcome |
| POST | `/groups/{gid}/mls/application` | `application/mls-message` | Submit application message |
| GET | `/groups/{gid}/mls/application?since=<cursor>` | — | Fetch pending application messages |

**WebSocket push types** (notification only, sent via existing `PushMessage`):

| `push_type` | Trigger | Purpose |
|------------|---------|----------|
| `mls_commit` | New Commit posted | Wake wallet to process epoch change |
| `mls_welcome` | Welcome stored | Notify invited wallet |
| `mls_proposal` | Proposal posted | Notify members of pending proposal |
| `mls_application` | Application msg posted | Notify members of new group message |
| `group_credential_update` | Credential added/removed | Trigger credential sync |

**GroupRelay implementation:**

```go
// GroupRelay manages MLS message distribution via the engine's WebSocket sessions
type GroupRelay struct {
    manager *Manager
    store   GroupStore  // persists MLS messages, group membership
}

func (r *GroupRelay) BroadcastCommit(ctx context.Context, groupID, senderID string, commit []byte, epoch uint64) error {
    // 1. Persist first (already done by REST handler before calling this)
    // 2. Notify connected members
    members, _ := r.store.GetMembers(ctx, groupID)
    for _, m := range members {
        if m.UserID == senderID { continue }
        if session, err := r.manager.GetSessionByUser(m.UserID); err == nil {
            _ = session.Send(&PushMessage{
                Message:  Message{Type: TypePush, Timestamp: Now()},
                PushType: "mls_commit",
                GroupID:  groupID,
                Epoch:    epoch,
            })
        }
        // Offline members need no explicit queuing — the commit is already
        // persisted; they will fetch via GET on reconnect.
    }
    return nil
}
```

### 8.3 Application-Level Messaging

MLS `mls_application` messages provide an encrypted, authenticated, forward-secret channel between group wallets. This serves the EU business wallet requirement for an underlying messaging layer without requiring separate messaging infrastructure.

The transport is identical to protocol messages: `POST /groups/{gid}/mls/application` to submit, WebSocket push to notify, `GET` to poll. The engine never decrypts the payload — it is end-to-end encrypted under the group's MLS epoch key.

Use cases for application messages:
- Credential status change notifications ("credential X revoked")
- Presentation receipts ("credential Y was presented to verifier Z")
- Group policy change proposals (higher-level than MLS proposals)
- Business process coordination (supply chain attestations, signing ceremonies)

### 8.3 Always-Online Agents

An always-online agent is a headless wallet running as part of (or alongside) the engine. Agents:
- Maintain a persistent virtual session (no WebSocket — local in-process)
- Hold their own MLS leaf node credentials
- Sign presentations without human interaction (policy-gated)
- Serve as persistent group presence when human wallets are offline

```go
// AgentSession is a virtual session for always-online agents
type AgentSession struct {
    Session                    // embeds for API compatibility
    keyStore AgentKeyStore     // HSM or software key storage
}

// RequestSign signs locally instead of sending to WebSocket
func (a *AgentSession) RequestSign(ctx context.Context, flowID string,
    action SignAction, params SignRequestParams) (*SignResponseMessage, error) {
    signature, err := a.keyStore.Sign(params.KeyID, params.Payload)
    return &SignResponseMessage{Signature: signature}, err
}
```

**Key management for agents**:
- Production deployments should use HSM/PKCS#11 for agent private keys
- MLS operations run Go-side (not WASM) — options include CGO binding to OpenMLS or a pure-Go MLS implementation
- The agent is the natural "group admin" role — it processes add/remove operations, handles credential re-issuance on ejection, and maintains the canonical group state

### 8.4 Agent as Group Admin

The always-online agent model resolves several design tensions:

| Concern | Agent Resolution |
|---------|-----------------|
| MLS Commit ordering | Agent serializes all commits as the designated committer |
| Credential re-issuance on ejection | Agent triggers re-issuance immediately, no waiting for human wallets |
| Offline member catch-up | Agent maintains canonical state; reconnecting members sync from it |
| OID4VP presentation on behalf of org | Agent can present group credentials for automated verifier requests |
| Key rotation scheduling | Agent performs periodic MLS Update+Commit for forward secrecy |

## 9. EU Business Wallet Considerations

### 9.1 Multiple Names / Aliases

An EU business wallet represents a legal entity that may operate under multiple names (legal name, trade name, branch names). The group model supports this via a subject alias registry:

```typescript
type GroupWalletState = {
  // ...existing fields...
  aliases: SubjectAlias[];
}

type SubjectAlias = {
  aliasId: string;
  name: string;             // e.g. "Acme Corp", "Acme GmbH"
  credentials: string[];    // credential IDs bound to this alias
  policy: AliasPolicy;      // who can present under this name
}
```

Each alias may have its own set of credentials (PID, EAAs) issued to that name. Group members can present credentials for any alias they have permission for, per `AliasPolicy`.

### 9.2 Messaging Layer for Business Processes

The EU business wallet expects an underlying messaging layer for:
- Credential exchange coordination (e.g. supply chain attestations)
- Multi-party verification workflows
- Status notifications (credential revocation, renewal reminders)

The MLS application message channel provides this without additional infrastructure. The engine's `GroupRelay` + `PushMessage` delivers these to connected wallets; offline members receive them on reconnect.

### 9.3 Regulatory Alignment

- **eIDAS2 EUDI Wallet**: The group model maps to "legal person wallet" with multiple natural person representatives
- **ARF (Architecture Reference Framework)**: Group credentials align with the concept of "organisational attestations" where the organisation's wallet holds EAAs presented by authorised employees
- **PID binding**: The organisation PID is a group credential; individual PIDs remain in personal containers

## 10. One-Shot Credential Sharing

### 10.1 Use Case

Share a credential with another wallet for a single presentation to a specific verifier, without granting ongoing group membership.

### 10.2 Design Options

**Option A: Direct Key Transfer (simple but irrevocable)**
- Wrap credential private key to recipient's public key (JWE, ECDH-ES+A256KW)
- Include scoped policy: `{ verifier: "did:web:v.example.com", maxUses: 1, expiresAt: "..." }`
- **Risk**: Once key material is transferred, it cannot be unsent. The policy is advisory — a malicious recipient can ignore it.

**Option B: Proxy Presentation (recommended)**
- The credential holder's wallet (or always-online agent) performs the presentation on behalf of the requester
- Requester sends a "presentation request" via the engine; agent/wallet signs and submits the VP directly
- **Advantage**: Key material never leaves the holder's control
- **Requirement**: The holder or their agent must be online at presentation time

**Option C: Short-Lived Derived Credential**
- Issue a short-TTL credential specifically for this presentation
- Requires issuer cooperation (re-issuance API)
- Clean revocation semantics

### 10.3 Recommendation

Prefer **Option B (proxy presentation)** for one-shot sharing. The always-online agent model (§8.3) makes this practical — the agent is always available to proxy presentations.

For cases where the holder must be offline, **Option C** with issuer-side TTL is the secure alternative. **Option A** should only be used when the trust relationship justifies sharing raw key material (e.g., within a tightly controlled organisation).

### 10.4 Security Implications for Ejection

One-shot sharing via direct key transfer (Option A) creates the same ejection problem as group membership: the recipient has the private key and can sign arbitrary presentations until the credential is revoked. This reinforces the preference for proxy presentation — there is no "ejection" because the key was never shared.

## 11. Implementation Phases

### Phase 1: Foundation
- [ ] Add `mlsIdentityKey` and `groupMemberships` to `WalletState`
- [ ] Integrate OpenMLS via WASM into the frontend build
- [ ] `GroupStateContainer` type and encryption/decryption using epoch key
- [ ] Backend: `/groups/*` endpoints for encrypted blob storage and MLS message relay
- [ ] Schema migration (WalletStateSchemaVersion**6**+ — V4/V5 are taken by PR #1025's ARKG types)
- [ ] Coordinate with PR #1025: `CredentialKeyPair` union, `arkgSeeds[]`, `externalPrivateKey` must be available for shareability checks
- [ ] Engine: `GroupRelay` service for MLS message fanout via `PushMessage`

### Phase 2: Basic Group Operations
- [ ] Create group, invite members (MLS Welcome), remove members (MLS Remove)
- [ ] Share credentials into group (move credential + keypair into group state)
- [ ] Any member can present group credentials
- [ ] Group listing and management UI
- [ ] Subject alias registry (multiple names per group)

### Phase 3: Engine & Agent
- [ ] Always-online `AgentSession` with local key storage
- [ ] Agent as MLS group admin (serialized commits, automatic re-issuance)
- [ ] Proxy presentation via agent (one-shot sharing, Option B)
- [ ] Application-level messaging via MLS channel
- [ ] Offline message queue and reconnect sync

### Phase 4: Policy & Governance
- [ ] Integrate `go-spocp` into go-wallet-backend engine as `SigningPolicy`
- [ ] SPOCP rules for credential shareability (key_type, format, issuer)
- [ ] SPOCP rules for signing key selection (hardware vs. software per action)
- [ ] Policy-gate `BaseHandler.RequestSign` with SPOCP evaluation
- [ ] Block sharing of hardware-bound credentials into groups
- [ ] Per-tenant default SPOCP rules in configuration
- [ ] Per-group SPOCP rule overrides (stored in `GroupWalletState.spocpRules`)
- [ ] Role-based permissions (GroupPolicy)
- [ ] Credential rotation on member removal
- [ ] Audit trail (event history: who presented what, when)
- [ ] Quorum-based presentation
- [ ] Alias-level presentation policies

### Phase 5: Advanced Binding & EU Compliance
- [ ] Integrate [zk-cred-longfellow](https://github.com/abetterinternet/zk-cred-longfellow) as WASM component for high-privacy ZK anonymous credentials from ECDSA
- [ ] Longfellow mdoc_zk prover/verifier integration for unlinkable selective disclosure
- [ ] Group DIDs (did:web or did:tdw)
- [ ] Delegation chains (issuer-aware group credentials)
- [ ] Threshold signatures for high-assurance use cases
- [ ] HSM/PKCS#11 integration for agent key management
- [ ] eIDAS2 / ARF alignment for organisational attestations

## 12. Open Questions

1. **Issuer awareness**: Should issuers be aware of group credentials? If so, what metadata is needed in the issuance request?
2. **Verifier experience**: How does a verifier distinguish a group presentation from an individual one? Does it matter?
3. **Notification delivery**: How do group members learn about new commits/proposals? Polling vs. push (WebSocket, push notifications)?
4. **Conflict resolution**: What happens when two members add credentials concurrently? The event-sourced merge handles this technically, but what about semantic conflicts?
5. **Cross-tenant groups**: Can groups span tenants in a multi-tenant deployment?
6. **Revocation propagation**: When a group credential is revoked, how quickly do all members learn about it?
7. **Go-side MLS implementation**: Pure Go (limited options) vs. CGO binding to OpenMLS for the always-online agent? Performance and deployment implications.
8. **Agent authorization model**: How does an agent prove to a verifier that it is authorized to present on behalf of the organisation? Bearer token? Delegation VC?
9. **One-shot vs. group boundary**: At what trust level does one-shot sharing become impractical and full group membership is required?
10. **EU regulatory review**: Which ARF requirements constrain the design? Specific ETSI TS standards for organisational wallets?
11. **SPOCP rule distribution**: How are issuer-specified SPOCP constraints ("this credential requires hardware keys") communicated? Credential metadata extension? OID4VCI metadata field?
12. **Policy conflict resolution**: When tenant, group, and issuer SPOCP rules conflict, what is the merge order? Strictest-wins (intersection) seems safest.
13. **Hardware key detection**: ~~How does the wallet reliably determine `KeyBindingType`?~~ **Resolved by PR #1025**: `'externalPrivateKey' in keypair` is the concrete binary test. No heuristics needed — the `CredentialKeyPair` union type encodes key binding at the schema level.
14. **SPOCP rule authoring**: Who writes the SPOCP rules? Tenant admins need a UI or DSL that maps to S-expressions without requiring knowledge of SPOCP syntax.
15. **Per-authenticator credential tracking**: ~~How does the wallet track which credentials are bound to which FIDO authenticator?~~ **Resolved by PR #1025**: `WebauthnSignPrivateKeyArkg.credentialId` identifies the authenticator. `WalletState.arkgSeeds[]` lists all registered ARKG seeds with `credentialId` references. The wallet can match any `externalPrivateKey.credentialId` to its parent `arkgSeed`.
16. **Multi-device vs. multi-wallet boundary**: When should a user register a second FIDO token on the same wallet account (same-user multi-device) vs. create a separate wallet and use MLS group sharing? UX guidance needed.
17. **FIDO token removal and credential orphaning**: If a user removes a FIDO token that is the only device hosting a hardware-bound credential, the credential becomes permanently inaccessible. Should the wallet warn / block removal?
18. **ARKG seed sharing in groups**: Can a group member's ARKG public seed be shared to allow other members to derive public keys for issuance? The derived credentials would still be bound to the original member's authenticator — is there a useful delegation pattern here?
19. **Schema version coordination**: PR #1025 uses Schema V4/V5. Group sharing needs V6+. How do we handle the case where group sharing ships before PR #1025 lands on master? Feature flag? Conditional schema migration?
20. **Batch instance allocation in groups**: For medium-privacy software-keyed credentials, how should instances be allocated to group members? Round-robin? Demand-based? Does `sigCount` tracking need to be coordinated across group members?
21. **Hardware-bound group re-issuance coordination**: When a group requires hardware-bound credentials for all members, each member must register their own ARKG seed and request issuance independently. How is this coordinated? Group-level issuance session? Agent-mediated batch issuance?

## 13. References

- [RFC 9420 - The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420)
- [OpenMLS](https://openmls.tech/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model-2.0/)
- [ISO 18013-5 (mDL)](https://www.iso.org/standard/69084.html)
- [eIDAS2 Architecture Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [zk-cred-longfellow](https://github.com/abetterinternet/zk-cred-longfellow) — Rust/WASM implementation of Anonymous Credentials from ECDSA ([Longfellow paper](https://eprint.iacr.org/2024/2010.pdf), [draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/))
- [WebAuthn Sign Extension v4](https://yubicolabs.github.io/webauthn-sign-extension/4/) — the `previewSign` extension spec
- [PR #1025: Add support for ARKG with WebAuthn sign extension preview](https://github.com/wwWallet/wallet-frontend/pull/1025) — introduces hardware-bound ARKG credential keys (Schema V4/V5)
- Current wallet keystore: `wallet-frontend/src/services/keystore.ts`
- Current wallet state schema: `wallet-frontend/src/services/WalletStateSchema.ts`
- ARKG sign extension module: `wallet-frontend/src/webauthn/sign-extension.ts` (PR #1025)
- Wallet state schema V4 (ARKG types): `wallet-frontend/src/services/WalletStateSchemaVersion4.ts` (PR #1025)
- Wallet state schema V5 (refined ARKG): `wallet-frontend/src/services/WalletStateSchemaVersion5.ts` (PR #1025)
- Engine handler pattern: `go-wallet-backend/internal/engine/handler.go`
- Engine messaging: `go-wallet-backend/internal/engine/messages.go`
- Engine sessions: `go-wallet-backend/internal/engine/session.go`
- SPOCP engine: `go-spocp/spocp.go` ([go-spocp](https://github.com/sirosfoundation/go-spocp))
- SPOCP S-expression syntax: `go-spocp/pkg/sexp/`
- SPOCP subsumption comparison: `go-spocp/pkg/compare/`
