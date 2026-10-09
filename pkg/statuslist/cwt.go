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
// (draft-ietf-oauth-status-list, CWT section; RFC 9052, RFC 8392). The COSE
// structure, header labels and signature verification come from
// github.com/veraison/go-cose; only the status-list policy is kept here.
const (
	coseHashSHA256 = -16
	coseHashSHA384 = -43
	coseHashSHA512 = -44

	cwtClaimIss = 1
	cwtClaimSub = 2
	cwtClaimExp = 4
	cwtClaimNbf = 5
	cwtClaimIat = 6
	// The draft registers status_list as 65533 and ttl as 65534. vc#703
	// (SUNET/vc pkg/tokenstatuslist) still emits status_list=65534 and
	// ttl=65535; that legacy layout is read when 65533 is absent and 65534
	// holds a map, so both sides interoperate.
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
	// UnmarshalCBOR requires exactly one tag 18 (draft-ietf-oauth-status-list
	// section 5.2 forbids the CWT tag 61 and untagged arrays), rejects
	// indefinite lengths and duplicate header labels, and requires crit to be
	// protected, non-empty and to name only protected labels.
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(body); err != nil {
		return parsedList{}, fmt.Errorf("%w: %v", errCWT, err)
	}
	prot, unprot := map[any]any(msg.Headers.Protected), map[any]any(msg.Headers.Unprotected)
	if err := checkHeaders(prot, unprot); err != nil {
		return parsedList{}, fmt.Errorf("%w header: %v", errCWT, err)
	}

	// typ must be integrity-protected: the unprotected header is not covered
	// by the signature, so it is not consulted for it.
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
	// Membership, not nil-ness, decides whether the standard claim is
	// present: a CBOR null decodes to nil but is a present (malformed)
	// claim, which must not fall back to the legacy layout.
	slRaw, ttlLabel := claims[cwtClaimStatusList], int64(cwtClaimTTL)
	if _, present := claims[cwtClaimStatusList]; !present {
		if _, isMap := anyMap(claims[cwtClaimLegacyStatusList]); isMap {
			slRaw, ttlLabel = claims[cwtClaimLegacyStatusList], cwtClaimLegacyTTL
		}
	} else {
		// Both layouts at once are ambiguous: the standard and legacy
		// spellings could carry different verdicts. Label 65534 is the
		// standard ttl and the legacy status_list, so a map there next to
		// the standard status_list (or both ttl spellings) is rejected.
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
	// The draft's CDDL uses the text keys "bits" and "lst"; the integer
	// labels 1 and 2 are also read (vc#703 writes those).
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
	// Present-but-invalid claims are rejected, never read as absent: a
	// text-valued exp would otherwise skip expiry validation and a
	// malformed iss would change the trust subject.
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

// checkHeaders enforces the COSE header rules that go-cose leaves to the
// caller: a label appears in at most one bucket (RFC 9052 section 3), and
// every critical label is understood (which excludes crit itself) and listed
// once (RFC 9052 section 3.1). go-cose has already checked that crit is only in
// the protected header, non-empty, and that each critical label is present
// in the protected header.
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

// decodeClaims reads a CWT claims set. Claim keys may be integers or text
// strings and the status-list profile permits additional claims, so the
// map is decoded with mixed keys: the integer-labelled claims are returned
// and text-labelled ones (extensions) are ignored. A repeated key, a label
// that is neither an integer nor a text string, or a null/undefined map is
// an error.
func decodeClaims(b []byte) (map[int64]any, error) {
	var raw map[any]any
	if err := claimsDecMode.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	// CBOR null and undefined decode into a nil map without an error; a map
	// is required here (an empty map is fine).
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

// cwtString reads an optional text claim; a present claim of another type, or
// one that is empty or only whitespace, is an error (never read as absent, which
// would change the trust subject).
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

// cwtInt reads an optional NumericDate/integer claim; a present claim that is
// not an integer is an error.
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

// signerChain returns the x5chain that carries the signer certificate.
// RFC 9360 section 2: "The end-entity certificate MUST be integrity
// protected by COSE. This can, for example, be done by sending the header
// parameter in the protected header, sending an 'x5chain' in the unprotected
// header combined with an 'x5t' in the protected header, or including the
// end-entity certificate in the external_aad." An x5chain in the protected
// header is accepted; one only in the unprotected header is accepted solely
// when the protected header holds an x5t that matches its end-entity
// certificate. Otherwise the chain could be swapped without invalidating the
// signature, changing the trust decision.
func signerChain(prot, unprot map[any]any) ([][]byte, error) {
	if v, ok := prot[cose.HeaderLabelX5Chain]; ok {
		chain, err := x5chain(v)
		if err != nil || len(chain) == 0 {
			return chain, err
		}
		// A protected x5t is validated whenever it is present, so a token
		// cannot carry a (possibly critical) mismatching certificate hash
		// and still yield a verdict.
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

// verifyCOSE verifies the COSE_Sign1 signature through go-cose. Only the
// ECDSA algorithms are accepted (the allowlist keeps go-cose from also being
// pointed at RSA or EdDSA keys), and the key's curve must be the one the
// algorithm names: go-cose derives only the hash from the algorithm, so an
// ES256 label over a P-384 key would otherwise verify.
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

// member looks a status_list member up by its text key or by any integer
// encoding (int64 or uint64) of its numeric label. A map carrying both
// spellings is rejected, even when the values agree: an implementation that
// reads only the other spelling could otherwise derive a different verdict
// from the same signed token.
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
