// Package taggedbinary provides utilities for handling tagged binary encoding.
// This encoding is used by the wallet-frontend to represent binary data in JSON.
// Binary data (Uint8Array/ArrayBuffer) is encoded as {"$b64u": "base64url-string"}.
package taggedbinary

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const tagKey = "$b64u"

// DecodeJSON transforms a JSON object with tagged binary values into plain base64url strings.
// Input:  {"rawId": {"$b64u": "SGVsbG8"}, "name": "test"}
// Output: {"rawId": "SGVsbG8", "name": "test"}
func DecodeJSON(data []byte) ([]byte, error) {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	decoded := decodeValue(obj)

	result, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal decoded JSON: %w", err)
	}

	return result, nil
}

// decodeValue recursively processes a JSON value, converting tagged binary to plain strings.
func decodeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		// Check if this is a tagged binary object
		if b64u, ok := val[tagKey]; ok && len(val) == 1 {
			// This is a tagged binary value, return just the base64url string
			if str, ok := b64u.(string); ok {
				return str
			}
		}
		// Regular object - recursively decode all values
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[k] = decodeValue(v)
		}
		return result

	case []interface{}:
		// Array - recursively decode all elements
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = decodeValue(v)
		}
		return result

	default:
		// Primitive value - return as-is
		return val
	}
}

// EncodeJSON transforms a JSON object with plain base64url binary strings into tagged binary format.
// This is the inverse of DecodeJSON.
// Note: This only encodes fields that are known to contain binary data (specified in binaryFields).
// Input:  {"rawId": "SGVsbG8", "name": "test"} with binaryFields=["rawId"]
// Output: {"rawId": {"$b64u": "SGVsbG8"}, "name": "test"}
func EncodeJSON(data []byte, binaryFields map[string]bool) ([]byte, error) {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	encoded := encodeValue(obj, binaryFields, "")

	result, err := json.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encoded JSON: %w", err)
	}

	return result, nil
}

// encodeValue recursively processes a JSON value, converting specified fields to tagged binary.
func encodeValue(v interface{}, binaryFields map[string]bool, path string) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			fieldPath := k
			if path != "" {
				fieldPath = path + "." + k
			}
			result[k] = encodeValue(v, binaryFields, fieldPath)
		}
		return result

	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = encodeValue(v, binaryFields, path)
		}
		return result

	case string:
		// Check if this field should be encoded as tagged binary
		if binaryFields[path] {
			return map[string]interface{}{tagKey: val}
		}
		return val

	default:
		return val
	}
}

// TransformReader wraps a reader and transforms tagged binary on the fly.
type TransformReader struct {
	data   []byte
	offset int
}

// NewTransformReader creates a TransformReader that decodes tagged binary from the given data.
func NewTransformReader(data []byte) (*TransformReader, error) {
	decoded, err := DecodeJSON(data)
	if err != nil {
		return nil, err
	}
	return &TransformReader{data: decoded}, nil
}

// Read implements io.Reader.
func (r *TransformReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// MustDecodeJSON is like DecodeJSON but returns the original data if decoding fails.
// This is useful when you want to gracefully handle both tagged and non-tagged formats.
func MustDecodeJSON(data []byte) []byte {
	decoded, err := DecodeJSON(data)
	if err != nil {
		return data
	}
	return decoded
}

// IsTaggedBinary checks if the JSON data contains tagged binary format.
func IsTaggedBinary(data []byte) bool {
	return bytes.Contains(data, []byte(`"$b64u"`))
}

// TaggedBytes wraps a byte slice to marshal as tagged binary format.
// When serialized to JSON, it produces {"$b64u": "base64url-encoded"}.
type TaggedBytes []byte

// MarshalJSON implements json.Marshaler for TaggedBytes.
func (t TaggedBytes) MarshalJSON() ([]byte, error) {
	if t == nil {
		return []byte("null"), nil
	}
	// Encode to base64url (no padding)
	encoded := base64.RawURLEncoding.EncodeToString(t)
	return json.Marshal(map[string]string{tagKey: encoded})
}

// UnmarshalJSON implements json.Unmarshaler for TaggedBytes.
func (t *TaggedBytes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*t = nil
		return nil
	}

	// Try tagged format first
	var tagged map[string]string
	if err := json.Unmarshal(data, &tagged); err == nil {
		if b64u, ok := tagged[tagKey]; ok {
			decoded, err := base64.RawURLEncoding.DecodeString(b64u)
			if err != nil {
				// Try with padding
				decoded, err = base64.URLEncoding.DecodeString(b64u)
				if err != nil {
					return fmt.Errorf("failed to decode base64url: %w", err)
				}
			}
			*t = decoded
			return nil
		}
	}

	// Try plain base64 string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		decoded, err := base64.RawURLEncoding.DecodeString(str)
		if err != nil {
			// Try with padding
			decoded, err = base64.URLEncoding.DecodeString(str)
			if err != nil {
				// Try standard base64
				decoded, err = base64.StdEncoding.DecodeString(str)
				if err != nil {
					return fmt.Errorf("failed to decode base64: %w", err)
				}
			}
		}
		*t = decoded
		return nil
	}

	return fmt.Errorf("invalid tagged bytes format")
}
