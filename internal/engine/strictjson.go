package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// The one decoding step for JSON that an issuer or the client hands the engine
// and the engine acts on for secret delivery (an advertisement, an error body,
// a key proof payload).
//
// encoding/json is lenient in three ways that let two readers see different
// documents: it matches keys case-insensitively, it keeps the last of repeated
// members, and a Decoder stops before trailing data. A document is read only
// when it is unambiguous; everything else is refused here, once, and callers
// decode the rest into typed structs.

// errAmbiguousJSON is wrapped by every refusal of decodeStrict that is about
// ambiguity (as opposed to syntax or a wrong type). It never carries content.
var errAmbiguousJSON = errors.New("ambiguous JSON")

// protocolMembers are the member names this engine reads from a document
// above. Another spelling in a different letter case ("TYPE", "Opening") is
// read as the canonical member by a case-insensitive decoder and as something
// else by a case-sensitive one: refused, wherever it appears.
var protocolMembers = []string{
	"type", "alg", "encoding", "path", "required", "opening", "commitment",
	"to_wallet", "to_issuer", "auxiliary_data", "auxiliary_data_supported",
	"credential_metadata", "error",
}

// decodeStrict decodes data into v only if data is one JSON value without
// trailing data, in which no object repeats a member name, has two names that
// differ only in letter case, or spells a protocol member name in another case.
// Syntax errors and values of the wrong type for v are errors too.
func decodeStrict(data []byte, v any) error {
	if err := checkUnambiguous(data, -1); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// checkUnambiguous is the walk behind decodeStrict. depth limits it to the
// outermost depth levels of objects (1: only the top-level object's names);
// a negative depth checks the whole document.
func checkUnambiguous(data []byte, depth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []map[string]struct{} // names of each open object; nil for an array
	expectKey := []bool{}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if n := len(expectKey); n > 0 && stack[n-1] != nil {
					expectKey[n-1] = true // this container is the member's value
				}
				if d == '{' {
					stack = append(stack, map[string]struct{}{})
				} else {
					stack = append(stack, nil)
				}
				expectKey = append(expectKey, d == '{')
			default:
				stack, expectKey = stack[:len(stack)-1], expectKey[:len(expectKey)-1]
			}
			if len(stack) == 0 {
				break
			}
			continue
		}
		n := len(stack)
		if n == 0 {
			break // a scalar document
		}
		if stack[n-1] == nil {
			continue
		}
		if !expectKey[n-1] { // a scalar value
			expectKey[n-1] = true
			continue
		}
		expectKey[n-1] = false
		if depth >= 0 && objectDepth(stack) > depth {
			continue
		}
		if key, ok := tok.(string); ok {
			if err := recordName(stack[n-1], key); err != nil {
				return err
			}
		}
	}
	// Reading stopped at the end of the first value; anything after it is
	// data another decoder would see.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errAmbiguousJSON
	}
	return nil
}

// objectDepth counts the open objects in stack.
func objectDepth(stack []map[string]struct{}) int {
	n := 0
	for _, s := range stack {
		if s != nil {
			n++
		}
	}
	return n
}

// recordName adds a member name to an object's set, refusing a repeat, a
// case-variant of another name, and a case-variant of a protocol member.
func recordName(names map[string]struct{}, key string) error {
	if _, seen := names[key]; seen {
		return errAmbiguousJSON
	}
	for other := range names {
		if strings.EqualFold(other, key) {
			return errAmbiguousJSON
		}
	}
	for _, p := range protocolMembers {
		if key != p && strings.EqualFold(key, p) {
			return errAmbiguousJSON
		}
	}
	names[key] = struct{}{}
	return nil
}

// containsMember reports whether any object anywhere in a decoded JSON value
// has a member named name. A document that passed decodeStrict spells each
// protocol member exactly one way, so the comparison is exact.
func containsMember(v any, name string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, el := range x {
			if k == name || containsMember(el, name) {
				return true
			}
		}
	case []any:
		for _, el := range x {
			if containsMember(el, name) {
				return true
			}
		}
	}
	return false
}
