package statuslist

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// COSE / CWT constants for the CWT form of a Status List Token
// (draft-ietf-oauth-status-list, CWT section; RFC 9052, RFC 8392).
const (
	coseTagSign1 = 18
	cwtTag       = 61

	coseHdrAlg     = 1
	coseHdrTyp     = 16 // "type" header parameter
	coseHdrX5Chain = 33 // RFC 9360

	coseAlgES256 = -7
	coseAlgES384 = -35
	coseAlgES512 = -36

	cwtClaimIss = 1
	cwtClaimSub = 2
	cwtClaimExp = 4
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
func (c *Checker) parseCWT(ctx context.Context, body []byte, uri string) (int, []byte, time.Duration, error) {
	sign1, err := decodeSign1(body)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("%w: %v", errCWT, err)
	}
	prot, err := decodeHeaderMap(sign1.protected)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("%w protected header: %v", errCWT, err)
	}

	typ, _ := headerValue(prot, sign1.unprotected, coseHdrTyp).(string)
	if strings.TrimPrefix(strings.ToLower(typ), "application/") != cwtTypValue {
		return 0, nil, 0, fmt.Errorf("%w typ is %q, want %q", errCWT, typ, cwtTypValue)
	}
	alg, ok := toInt64(prot[coseHdrAlg])
	if !ok {
		return 0, nil, 0, fmt.Errorf("%w has no alg in its protected header", errCWT)
	}

	chain, err := x5chain(headerValue(prot, sign1.unprotected, coseHdrX5Chain))
	if err != nil {
		return 0, nil, 0, fmt.Errorf("%w x5chain: %v", errCWT, err)
	}
	if len(chain) == 0 {
		return 0, nil, 0, ErrNoSignerKey
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("%w x5chain leaf: %v", errCWT, err)
	}
	if err := verifyCOSE(alg, leaf.PublicKey, sign1); err != nil {
		return 0, nil, 0, fmt.Errorf("%w signature: %v", errCWT, err)
	}
	km := &trust.KeyMaterial{Type: "x5c"}
	for _, der := range chain {
		km.X5C = append(km.X5C, base64.StdEncoding.EncodeToString(der))
	}

	var claims map[int64]any
	if err := cbor.Unmarshal(sign1.payload, &claims); err != nil {
		return 0, nil, 0, fmt.Errorf("%w payload: %v", errCWT, err)
	}
	slRaw, ttlLabel := claims[cwtClaimStatusList], int64(cwtClaimTTL)
	if slRaw == nil {
		if _, isMap := intKeyMap(claims[cwtClaimLegacyStatusList]); isMap {
			slRaw, ttlLabel = claims[cwtClaimLegacyStatusList], cwtClaimLegacyTTL
		}
	}
	sl, ok := intKeyMap(slRaw)
	if !ok {
		return 0, nil, 0, fmt.Errorf("%w has no status_list claim", errCWT)
	}
	bits, ok := toInt64(sl[statusListKeyBits])
	if !ok {
		return 0, nil, 0, fmt.Errorf("%w status_list has no bits", errCWT)
	}
	lst, ok := sl[statusListKeyLst].([]byte)
	if !ok || len(lst) == 0 {
		return 0, nil, 0, fmt.Errorf("%w status_list has no lst", errCWT)
	}
	sub, _ := claims[cwtClaimSub].(string)
	iss, _ := claims[cwtClaimIss].(string)
	return c.accept(ctx, uri, km, listClaims{
		sub: sub, iss: iss,
		iat: optInt(claims[cwtClaimIat]), exp: optInt(claims[cwtClaimExp]), ttl: optInt(claims[ttlLabel]),
		bits: int(bits), lst: lst,
	})
}

type sign1 struct {
	protected, payload, signature []byte
	unprotected                   map[int64]any
}

// decodeSign1 reads a COSE_Sign1, tagged (18, optionally inside the CWT tag
// 61) or untagged.
func decodeSign1(data []byte) (*sign1, error) {
	for i := 0; i < 2 && len(data) > 0 && data[0]>>5 == 6; i++ {
		var tag cbor.RawTag
		if err := cbor.Unmarshal(data, &tag); err != nil {
			return nil, err
		}
		if tag.Number != coseTagSign1 && tag.Number != cwtTag {
			return nil, fmt.Errorf("unexpected CBOR tag %d", tag.Number)
		}
		data = tag.Content
	}
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(data, &arr); err != nil || len(arr) != 4 {
		return nil, errors.New("not a COSE_Sign1 array")
	}
	out := &sign1{}
	if err := cbor.Unmarshal(arr[0], &out.protected); err != nil {
		return nil, fmt.Errorf("protected header: %w", err)
	}
	if err := cbor.Unmarshal(arr[1], &out.unprotected); err != nil {
		return nil, fmt.Errorf("unprotected header: %w", err)
	}
	if err := cbor.Unmarshal(arr[2], &out.payload); err != nil || out.payload == nil {
		return nil, errors.New("missing payload")
	}
	if err := cbor.Unmarshal(arr[3], &out.signature); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return out, nil
}

func decodeHeaderMap(b []byte) (map[int64]any, error) {
	m := map[int64]any{}
	if len(b) == 0 {
		return m, nil
	}
	return m, cbor.Unmarshal(b, &m)
}

// headerValue looks a label up in the protected then the unprotected header.
func headerValue(prot, unprot map[int64]any, label int64) any {
	if v, ok := prot[label]; ok {
		return v
	}
	return unprot[label]
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

// verifyCOSE checks an ECDSA COSE_Sign1 signature (RFC 9052 section 4.4).
func verifyCOSE(alg int64, pub crypto.PublicKey, s *sign1) error {
	var curve elliptic.Curve
	var h crypto.Hash
	switch alg {
	case coseAlgES256:
		curve, h = elliptic.P256(), crypto.SHA256
	case coseAlgES384:
		curve, h = elliptic.P384(), crypto.SHA384
	case coseAlgES512:
		curve, h = elliptic.P521(), crypto.SHA512
	default:
		return fmt.Errorf("unsupported COSE alg %d", alg)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != curve {
		return fmt.Errorf("key does not match alg %d", alg)
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(s.signature) != 2*size {
		return errors.New("bad signature length")
	}
	tbs, err := cbor.Marshal([]any{"Signature1", s.protected, []byte{}, s.payload})
	if err != nil {
		return err
	}
	hh := h.New()
	hh.Write(tbs)
	r := new(big.Int).SetBytes(s.signature[:size])
	sv := new(big.Int).SetBytes(s.signature[size:])
	if !ecdsa.Verify(key, hh.Sum(nil), r, sv) {
		return errors.New("signature does not verify")
	}
	return nil
}

// intKeyMap normalises the map shapes fxamacker/cbor produces for integer keys.
func intKeyMap(raw any) (map[int64]any, bool) {
	switch m := raw.(type) {
	case map[int64]any:
		return m, true
	case map[any]any:
		out := make(map[int64]any, len(m))
		for k, v := range m {
			if n, ok := toInt64(k); ok {
				out[n] = v
			}
		}
		return out, true
	}
	return nil, false
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

func optInt(v any) *int64 {
	if n, ok := toInt64(v); ok {
		return &n
	}
	return nil
}
