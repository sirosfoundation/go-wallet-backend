package statuslist

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// COSE / CWT constants for the CWT form of a Status List Token
// (draft-ietf-oauth-status-list; RFC 9052, RFC 8392). COSE parsing and
// signature verification are go-cose's; only status-list policy lives here.
const (
	coseHashSHA256 = -16
	coseHashSHA384 = -43
	coseHashSHA512 = -44

	cwtClaimIss = 1
	cwtClaimSub = 2
	cwtClaimExp = 4
	cwtClaimNbf = 5
	cwtClaimIat = 6
	// The draft registers status_list=65533 and ttl=65534. SUNET/vc emits the
	// legacy layout (65534, 65535), read when 65533 is absent and 65534 is a map.
	cwtClaimStatusList       = 65533
	cwtClaimTTL              = 65534
	cwtClaimLegacyStatusList = 65534
	cwtClaimLegacyTTL        = 65535

	statusListKeyBits = 1
	statusListKeyLst  = 2

	cwtTypValue = "statuslist+cwt"
)

var errCWT = errors.New("status list CWT")

// parseCWT verifies a CWT-form Status List Token and applies the same claim
// checks and trust decision as the JWT form.
func (c *Checker) parseCWT(ctx context.Context, body []byte, uri string) (parsedList, error) {
	// UnmarshalCBOR requires exactly one tag 18 (draft §5.2), rejects
	// indefinite lengths and duplicate header labels, and validates crit.
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(body); err != nil {
		return parsedList{}, fmt.Errorf("%w: %v", errCWT, err)
	}
	prot, unprot := map[any]any(msg.Headers.Protected), map[any]any(msg.Headers.Unprotected)
	if err := checkHeaders(prot, unprot); err != nil {
		return parsedList{}, fmt.Errorf("%w header: %v", errCWT, err)
	}

	// typ is read from the protected header only (the unprotected is unsigned).
	typ, _ := prot[cose.HeaderLabelType].(string)
	if strings.TrimPrefix(strings.ToLower(typ), "application/") != cwtTypValue {
		return parsedList{}, fmt.Errorf("%w typ is %q, want %q", errCWT, typ, cwtTypValue)
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return parsedList{}, fmt.Errorf("%w has no usable alg in its protected header: %v", errCWT, err)
	}

	chain, err := signerChain(prot, unprot)
	if err != nil {
		return parsedList{}, fmt.Errorf("%w x5chain: %v", errCWT, err)
	}
	if len(chain) == 0 {
		return parsedList{}, ErrNoSignerKey
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return parsedList{}, fmt.Errorf("%w x5chain leaf: %v", errCWT, err)
	}
	if err := verifyCOSE(alg, leaf.PublicKey, &msg); err != nil {
		return parsedList{}, classify(ReasonSignatureInvalid, fmt.Errorf("%w signature: %v", errCWT, err))
	}
	km := &trust.KeyMaterial{Type: "x5c"}
	for _, der := range chain {
		km.X5C = append(km.X5C, base64.StdEncoding.EncodeToString(der))
	}

	claims, err := decodeClaims(msg.Payload)
	if err != nil {
		return parsedList{}, fmt.Errorf("%w payload: %v", errCWT, err)
	}
	// Presence is by membership: a CBOR null is a present, malformed claim and
	// must not fall back to the legacy layout.
	slRaw, ttlLabel := claims[cwtClaimStatusList], int64(cwtClaimTTL)
	if _, present := claims[cwtClaimStatusList]; !present {
		if _, isMap := anyMap(claims[cwtClaimLegacyStatusList]); isMap {
			slRaw, ttlLabel = claims[cwtClaimLegacyStatusList], cwtClaimLegacyTTL
		}
	} else {
		// Both layouts at once are ambiguous (65534 is the standard ttl and the
		// legacy status_list), so reject them.
		if _, isMap := anyMap(claims[cwtClaimLegacyStatusList]); isMap {
			return parsedList{}, fmt.Errorf("%w has both the standard and the legacy status_list claim", errCWT)
		}
		_, std := claims[cwtClaimTTL]
		if _, legacy := claims[cwtClaimLegacyTTL]; std && legacy {
			return parsedList{}, fmt.Errorf("%w has both the standard and the legacy ttl claim", errCWT)
		}
	}
	sl, ok := anyMap(slRaw)
	if !ok {
		return parsedList{}, fmt.Errorf("%w has no status_list claim", errCWT)
	}
	// The draft uses text keys "bits"/"lst"; the integer labels 1/2 (SUNET/vc) are also read.
	bitsRaw, err := member(sl, "bits", statusListKeyBits)
	if err != nil {
		return parsedList{}, fmt.Errorf("%w status_list: %v", errCWT, err)
	}
	lstRaw, err := member(sl, "lst", statusListKeyLst)
	if err != nil {
		return parsedList{}, fmt.Errorf("%w status_list: %v", errCWT, err)
	}
	bits, ok := toInt64(bitsRaw)
	if !ok {
		return parsedList{}, fmt.Errorf("%w status_list has no bits", errCWT)
	}
	lst, ok := lstRaw.([]byte)
	if !ok || len(lst) == 0 {
		return parsedList{}, fmt.Errorf("%w status_list has no lst", errCWT)
	}
	// Present-but-invalid claims are rejected, never read as absent (a text exp
	// would skip expiry; a malformed iss would change the trust subject).
	var lc listClaims
	if lc.sub, err = cwtString(claims, cwtClaimSub, "sub"); err != nil {
		return parsedList{}, err
	}
	if lc.iss, err = cwtString(claims, cwtClaimIss, "iss"); err != nil {
		return parsedList{}, err
	}
	for _, f := range []struct {
		dst   **int64
		label int64
		name  string
	}{
		{&lc.iat, cwtClaimIat, "iat"}, {&lc.exp, cwtClaimExp, "exp"},
		{&lc.nbf, cwtClaimNbf, "nbf"}, {&lc.ttl, ttlLabel, "ttl"},
	} {
		if *f.dst, err = cwtInt(claims, f.label, f.name); err != nil {
			return parsedList{}, err
		}
	}
	lc.bits, lc.lst = int(bits), lst
	return c.accept(ctx, uri, km, lc)
}

// understoodHeaders are the header labels this verifier processes; a label
// listed in crit must be one of them (RFC 9052 section 3.1).
var understoodHeaders = map[int64]bool{
	cose.HeaderLabelAlgorithm: true, cose.HeaderLabelType: true,
	cose.HeaderLabelX5Chain: true, cose.HeaderLabelX5T: true,
}

// checkHeaders enforces the header rules go-cose leaves to the caller: a label
// is in at most one bucket (RFC 9052 §3), and every critical label is
// understood and listed once (§3.1).
func checkHeaders(prot, unprot map[any]any) error {
	for k := range unprot {
		if _, dup := prot[k]; dup {
			return fmt.Errorf("label %v is in both the protected and unprotected header", k)
		}
	}
	crit, err := cose.ProtectedHeader(prot).Critical()
	if err != nil {
		return err
	}
	seen := make(map[int64]bool, len(crit))
	for _, e := range crit {
		label, ok := toInt64(e)
		if !ok {
			return fmt.Errorf("critical header %v is not understood", e)
		}
		if seen[label] {
			return fmt.Errorf("critical header %d is listed more than once", label)
		}
		seen[label] = true
		if !understoodHeaders[label] {
			return fmt.Errorf("critical header %d is not understood", label)
		}
	}
	return nil
}

// claimsDecMode rejects a map that repeats a key.
var claimsDecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// decodeClaims reads a CWT claims set and returns the integer-labelled claims;
// text-labelled extensions are ignored. A repeated key, another label type, or
// a null/undefined map is an error.
func decodeClaims(b []byte) (map[int64]any, error) {
	var raw map[any]any
	if err := claimsDecMode.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	// CBOR null and undefined decode to a nil map without error.
	if raw == nil {
		return nil, errors.New("not a CBOR map (null or undefined)")
	}
	ints := make(map[int64]any, len(raw))
	for k, v := range raw {
		if label, ok := toInt64(k); ok {
			ints[label] = v
		} else if _, ok := k.(string); !ok {
			return nil, fmt.Errorf("label of type %T is neither an integer nor a text string", k)
		}
	}
	return ints, nil
}

// cwtString reads an optional text claim; a present non-text or blank claim is an error.
func cwtString(claims map[int64]any, label int64, name string) (string, error) {
	v, ok := claims[label]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w claim %s (%d) is %T, want text", errCWT, name, label, v)
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%w claim %s (%d) is empty", errCWT, name, label)
	}
	return s, nil
}

// cwtInt reads an optional integer claim; a present non-integer is an error.
func cwtInt(claims map[int64]any, label int64, name string) (*int64, error) {
	v, ok := claims[label]
	if !ok {
		return nil, nil
	}
	n, ok := toInt64(v)
	if !ok {
		return nil, fmt.Errorf("%w claim %s (%d) is %T, want an integer", errCWT, name, label, v)
	}
	return &n, nil
}

// signerChain returns the signer's x5chain. Per RFC 9360 §2 the end-entity
// certificate must be integrity protected: a protected x5chain is accepted; an
// unprotected one only with a matching protected x5t. Otherwise the chain could
// be swapped without invalidating the signature.
func signerChain(prot, unprot map[any]any) ([][]byte, error) {
	if v, ok := prot[cose.HeaderLabelX5Chain]; ok {
		chain, err := x5chain(v)
		if err != nil || len(chain) == 0 {
			return chain, err
		}
		// A present protected x5t must match, even if not needed.
		if _, has := prot[cose.HeaderLabelX5T]; has {
			if err := checkX5T(prot[cose.HeaderLabelX5T], chain[0]); err != nil {
				return nil, fmt.Errorf("protected x5t: %v", err)
			}
		}
		return chain, nil
	}
	v, ok := unprot[cose.HeaderLabelX5Chain]
	if !ok {
		return nil, nil
	}
	chain, err := x5chain(v)
	if err != nil || len(chain) == 0 {
		return chain, err
	}
	if err := checkX5T(prot[cose.HeaderLabelX5T], chain[0]); err != nil {
		return nil, fmt.Errorf("unprotected x5chain is not integrity protected (RFC 9360 section 2): %v", err)
	}
	return chain, nil
}

// checkX5T verifies a protected x5t (COSE_CertHash, RFC 9360) against a
// certificate.
func checkX5T(v any, der []byte) error {
	arr, ok := v.([]any)
	if v == nil || !ok || len(arr) != 2 {
		return errors.New("no protected x5t binding the end-entity certificate")
	}
	alg, ok := toInt64(arr[0])
	if !ok {
		if n, isNeg := arr[0].(int64); isNeg {
			alg, ok = n, true
		}
	}
	want, isBytes := arr[1].([]byte)
	if !ok || !isBytes {
		return errors.New("malformed x5t")
	}
	var sum []byte
	switch alg {
	case coseHashSHA256:
		h := sha256.Sum256(der)
		sum = h[:]
	case coseHashSHA384:
		h := sha512.Sum384(der)
		sum = h[:]
	case coseHashSHA512:
		h := sha512.Sum512(der)
		sum = h[:]
	default:
		return fmt.Errorf("unsupported x5t hash algorithm %d", alg)
	}
	if subtle.ConstantTimeCompare(sum, want) != 1 {
		return errors.New("x5t does not match the end-entity certificate")
	}
	return nil
}

// x5chain reads an x5chain header value: one DER certificate or an array.
func x5chain(v any) ([][]byte, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case []byte:
		return [][]byte{t}, nil
	case []any:
		out := make([][]byte, 0, len(t))
		for _, e := range t {
			b, ok := e.([]byte)
			if !ok {
				return nil, errors.New("entry is not a byte string")
			}
			out = append(out, b)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unexpected type %T", v)
}

// verifyCOSE verifies the COSE_Sign1 signature through go-cose. Only ECDSA is
// accepted, and the key's curve must match the algorithm (go-cose derives only
// the hash, so ES256 over a P-384 key would otherwise verify).
func verifyCOSE(alg cose.Algorithm, pub crypto.PublicKey, msg *cose.Sign1Message) error {
	var curve elliptic.Curve
	switch alg {
	case cose.AlgorithmES256:
		curve = elliptic.P256()
	case cose.AlgorithmES384:
		curve = elliptic.P384()
	case cose.AlgorithmES512:
		curve = elliptic.P521()
	default:
		return fmt.Errorf("unsupported COSE alg %d", alg)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != curve {
		return fmt.Errorf("key does not match alg %d", alg)
	}
	verifier, err := cose.NewVerifier(alg, key)
	if err != nil {
		return err
	}
	return msg.Verify(nil, verifier)
}

// anyMap normalises the map shapes fxamacker/cbor produces for a CBOR map with
// text or integer keys.
func anyMap(raw any) (map[any]any, bool) {
	switch m := raw.(type) {
	case map[any]any:
		return m, m != nil
	case map[int64]any:
		if m == nil {
			return nil, false
		}
		out := make(map[any]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out, true
	case map[string]any:
		if m == nil {
			return nil, false
		}
		out := make(map[any]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out, true
	}
	return nil, false
}

// member looks a status_list member up by text key or numeric label. Both
// spellings present is an error, even if equal, so no reader can see another verdict.
func member(m map[any]any, text string, label int64) (any, error) {
	tv, hasText := m[text]
	var iv any
	hasInt := false
	for k, v := range m {
		if n, ok := toInt64(k); ok && n == label {
			iv, hasInt = v, true
		}
	}
	if hasText && hasInt {
		return nil, fmt.Errorf("member %q is present as both %q and %d", text, text, label)
	}
	if hasText {
		return tv, nil
	}
	return iv, nil
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n > 1<<62 {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}
