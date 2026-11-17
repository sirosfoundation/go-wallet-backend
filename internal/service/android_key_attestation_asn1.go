package service

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// This file parses the Android Key Attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17), the KeyDescription of
// https://source.android.com/docs/security/features/keystore/attestation#schema
//
//	KeyDescription ::= SEQUENCE {
//	  attestationVersion         INTEGER,
//	  attestationSecurityLevel   SecurityLevel,
//	  keyMintVersion             INTEGER,     -- keymasterVersion before v100
//	  keyMintSecurityLevel       SecurityLevel,
//	  attestationChallenge       OCTET_STRING,
//	  uniqueId                   OCTET_STRING,
//	  softwareEnforced           AuthorizationList,
//	  hardwareEnforced           AuthorizationList }   -- teeEnforced before v100
//
// The parser reads only the members it needs, by tag, and skips every tag it
// does not know, so new attestation versions parse. It is hostile-input safe:
// every structure is bounded (input size, element counts) and malformed or
// ambiguous input (duplicate known tags, wrong types, trailing bytes in a
// member) is an error, never a panic and never a guess.

// OID of the attestation extension.
var oidAndroidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

const (
	// maxKeyDescriptionBytes bounds the extension value we parse. Real ones
	// are a few hundred bytes.
	maxKeyDescriptionBytes = 16 * 1024
	// maxASN1Elements bounds the members of any one SEQUENCE/SET we walk.
	maxASN1Elements = 256
	// maxAppIDEntries bounds package names and signature digests.
	maxAppIDEntries = 16
)

// Security levels of KeyDescription.
const (
	androidLevelSoftware           = 0
	androidLevelTrustedEnvironment = 1
	androidLevelStrongBox          = 2
)

// AuthorizationList tags used here.
const (
	akTagPurpose      = 1
	akTagAlgorithm    = 2
	akTagEcCurve      = 10
	akTagOrigin       = 702
	akTagRootOfTrust  = 704
	akTagOsPatchLevel = 706
	akTagAppID        = 709
)

// Values of those tags.
const (
	androidAlgorithmEC     = 3
	androidCurveP256       = 1
	androidOriginGenerated = 0
	androidPurposeSign     = 2
)

// androidRootOfTrust is the RootOfTrust of an AuthorizationList.
type androidRootOfTrust struct {
	DeviceLocked      bool
	VerifiedBootState int
}

// androidAppID is the AttestationApplicationId.
type androidAppID struct {
	Packages        []string
	SignatureDigest [][]byte
}

// androidAuthList is the subset of an AuthorizationList this verifier reads.
type androidAuthList struct {
	Purposes     []int
	Algorithm    *int
	EcCurve      *int
	Origin       *int
	RootOfTrust  *androidRootOfTrust
	OsPatchLevel *int
	AppID        *androidAppID
}

func (a *androidAuthList) hasPurpose(p int) bool {
	for _, v := range a.Purposes {
		if v == p {
			return true
		}
	}
	return false
}

// androidKeyDescription is a parsed KeyDescription.
type androidKeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel int
	KeymasterSecurityLevel   int
	Challenge                []byte
	Software                 androidAuthList
	TEE                      androidAuthList
}

var errASN1 = errors.New("malformed key description")

func asn1Err(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errASN1, fmt.Sprintf(format, a...))
}

// asn1Elements splits the content of a constructed value into its members.
func asn1Elements(content []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	rest := content
	for len(rest) > 0 {
		if len(out) >= maxASN1Elements {
			return nil, asn1Err("more than %d elements", maxASN1Elements)
		}
		var rv asn1.RawValue
		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return nil, asn1Err("%v", err)
		}
		if len(next) >= len(rest) {
			return nil, asn1Err("no progress")
		}
		out = append(out, rv)
		rest = next
	}
	return out, nil
}

// asn1Single decodes content that must hold exactly one element.
func asn1Single(content []byte) (asn1.RawValue, error) {
	els, err := asn1Elements(content)
	if err != nil {
		return asn1.RawValue{}, err
	}
	if len(els) != 1 {
		return asn1.RawValue{}, asn1Err("expected one element, found %d", len(els))
	}
	return els[0], nil
}

func rvInt(rv asn1.RawValue, tag int) (int, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != tag || rv.IsCompound {
		return 0, asn1Err("expected universal tag %d", tag)
	}
	var v int
	var err error
	if tag == asn1.TagEnum {
		var e asn1.Enumerated
		_, err = asn1.Unmarshal(rv.FullBytes, &e)
		v = int(e)
	} else {
		_, err = asn1.Unmarshal(rv.FullBytes, &v)
	}
	if err != nil {
		return 0, asn1Err("%v", err)
	}
	return v, nil
}

func rvOctets(rv asn1.RawValue) ([]byte, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagOctetString || rv.IsCompound {
		return nil, asn1Err("expected OCTET STRING")
	}
	return rv.Bytes, nil
}

func rvBool(rv asn1.RawValue) (bool, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagBoolean || rv.IsCompound {
		return false, asn1Err("expected BOOLEAN")
	}
	var b bool
	if _, err := asn1.Unmarshal(rv.FullBytes, &b); err != nil {
		return false, asn1Err("%v", err)
	}
	return b, nil
}

func rvSequenceOrSet(rv asn1.RawValue) ([]asn1.RawValue, error) {
	if rv.Class != asn1.ClassUniversal || !rv.IsCompound || (rv.Tag != asn1.TagSequence && rv.Tag != asn1.TagSet) {
		return nil, asn1Err("expected SEQUENCE or SET")
	}
	return asn1Elements(rv.Bytes)
}

func parseRootOfTrust(rv asn1.RawValue) (*androidRootOfTrust, error) {
	els, err := rvSequenceOrSet(rv)
	if err != nil {
		return nil, err
	}
	// verifiedBootKey, deviceLocked, verifiedBootState, [verifiedBootHash]
	if len(els) < 3 {
		return nil, asn1Err("rootOfTrust has %d members", len(els))
	}
	if _, err := rvOctets(els[0]); err != nil {
		return nil, err
	}
	locked, err := rvBool(els[1])
	if err != nil {
		return nil, err
	}
	state, err := rvInt(els[2], asn1.TagEnum)
	if err != nil {
		return nil, err
	}
	return &androidRootOfTrust{DeviceLocked: locked, VerifiedBootState: state}, nil
}

// parseAppID parses the content of attestationApplicationId, an OCTET STRING
// holding a DER SEQUENCE { SET OF package info, SET OF OCTET STRING digest }.
func parseAppID(octets []byte) (*androidAppID, error) {
	root, err := asn1Single(octets)
	if err != nil {
		return nil, err
	}
	els, err := rvSequenceOrSet(root)
	if err != nil {
		return nil, err
	}
	if len(els) < 2 {
		return nil, asn1Err("attestationApplicationId has %d members", len(els))
	}
	pkgs, err := rvSequenceOrSet(els[0])
	if err != nil {
		return nil, err
	}
	digests, err := rvSequenceOrSet(els[1])
	if err != nil {
		return nil, err
	}
	if len(pkgs) > maxAppIDEntries || len(digests) > maxAppIDEntries {
		return nil, asn1Err("too many application id entries")
	}
	out := &androidAppID{}
	for _, p := range pkgs {
		info, err := rvSequenceOrSet(p)
		if err != nil || len(info) < 1 {
			return nil, asn1Err("bad package info")
		}
		name, err := rvOctets(info[0])
		if err != nil {
			return nil, err
		}
		out.Packages = append(out.Packages, string(name))
	}
	for _, d := range digests {
		b, err := rvOctets(d)
		if err != nil {
			return nil, err
		}
		out.SignatureDigest = append(out.SignatureDigest, append([]byte(nil), b...))
	}
	return out, nil
}

// parseAuthList reads the members it knows from one AuthorizationList. A
// known tag that appears twice is an error: with two values the list is
// ambiguous, and picking one would let an attacker choose.
func parseAuthList(rv asn1.RawValue) (androidAuthList, error) {
	var out androidAuthList
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagSequence || !rv.IsCompound {
		return out, asn1Err("authorization list is not a SEQUENCE")
	}
	els, err := asn1Elements(rv.Bytes)
	if err != nil {
		return out, err
	}
	seen := make(map[int]bool)
	for _, el := range els {
		if el.Class != asn1.ClassContextSpecific || !el.IsCompound {
			return out, asn1Err("authorization list member is not an explicit context tag")
		}
		known := false
		switch el.Tag {
		case akTagPurpose, akTagAlgorithm, akTagEcCurve, akTagOrigin, akTagRootOfTrust, akTagOsPatchLevel, akTagAppID:
			known = true
		}
		if !known {
			continue // unknown tags (new versions, key size, digests, ...) are skipped
		}
		if seen[el.Tag] {
			return out, asn1Err("duplicate authorization tag %d", el.Tag)
		}
		seen[el.Tag] = true
		inner, err := asn1Single(el.Bytes)
		if err != nil {
			return out, err
		}
		switch el.Tag {
		case akTagPurpose:
			members, err := rvSequenceOrSet(inner)
			if err != nil {
				return out, err
			}
			for _, m := range members {
				v, err := rvInt(m, asn1.TagInteger)
				if err != nil {
					return out, err
				}
				out.Purposes = append(out.Purposes, v)
			}
		case akTagAlgorithm:
			v, err := rvInt(inner, asn1.TagInteger)
			if err != nil {
				return out, err
			}
			out.Algorithm = &v
		case akTagEcCurve:
			v, err := rvInt(inner, asn1.TagInteger)
			if err != nil {
				return out, err
			}
			out.EcCurve = &v
		case akTagOrigin:
			v, err := rvInt(inner, asn1.TagInteger)
			if err != nil {
				return out, err
			}
			out.Origin = &v
		case akTagOsPatchLevel:
			v, err := rvInt(inner, asn1.TagInteger)
			if err != nil {
				return out, err
			}
			out.OsPatchLevel = &v
		case akTagRootOfTrust:
			r, err := parseRootOfTrust(inner)
			if err != nil {
				return out, err
			}
			out.RootOfTrust = r
		case akTagAppID:
			octets, err := rvOctets(inner)
			if err != nil {
				return out, err
			}
			a, err := parseAppID(octets)
			if err != nil {
				return out, err
			}
			out.AppID = a
		}
	}
	return out, nil
}

// parseAndroidKeyDescription parses the value of the attestation extension.
func parseAndroidKeyDescription(der []byte) (*androidKeyDescription, error) {
	if len(der) == 0 || len(der) > maxKeyDescriptionBytes {
		return nil, asn1Err("extension size %d out of bounds", len(der))
	}
	var root asn1.RawValue
	rest, err := asn1.Unmarshal(der, &root)
	if err != nil {
		return nil, asn1Err("%v", err)
	}
	if len(rest) != 0 {
		return nil, asn1Err("trailing data after key description")
	}
	if root.Class != asn1.ClassUniversal || root.Tag != asn1.TagSequence || !root.IsCompound {
		return nil, asn1Err("key description is not a SEQUENCE")
	}
	els, err := asn1Elements(root.Bytes)
	if err != nil {
		return nil, err
	}
	if len(els) < 8 {
		return nil, asn1Err("key description has %d members", len(els))
	}
	kd := &androidKeyDescription{}
	if kd.AttestationVersion, err = rvInt(els[0], asn1.TagInteger); err != nil {
		return nil, err
	}
	if kd.AttestationSecurityLevel, err = rvInt(els[1], asn1.TagEnum); err != nil {
		return nil, err
	}
	if _, err = rvInt(els[2], asn1.TagInteger); err != nil {
		return nil, err
	}
	if kd.KeymasterSecurityLevel, err = rvInt(els[3], asn1.TagEnum); err != nil {
		return nil, err
	}
	if kd.Challenge, err = rvOctets(els[4]); err != nil {
		return nil, err
	}
	if _, err = rvOctets(els[5]); err != nil {
		return nil, err
	}
	if kd.Software, err = parseAuthList(els[6]); err != nil {
		return nil, err
	}
	if kd.TEE, err = parseAuthList(els[7]); err != nil {
		return nil, err
	}
	return kd, nil
}
