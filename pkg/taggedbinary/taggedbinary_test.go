package taggedbinary

import (
	"encoding/json"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "simple tagged binary",
			input: `{"rawId": {"$b64u": "SGVsbG8"}}`,
			want:  `{"rawId":"SGVsbG8"}`,
		},
		{
			name:  "nested tagged binary",
			input: `{"credential": {"rawId": {"$b64u": "SGVsbG8"}, "type": "public-key"}}`,
			want:  `{"credential":{"rawId":"SGVsbG8","type":"public-key"}}`,
		},
		{
			name:  "deeply nested tagged binary",
			input: `{"credential": {"response": {"authenticatorData": {"$b64u": "YXV0aA"}, "clientDataJSON": {"$b64u": "Y2xpZW50"}}}}`,
			want:  `{"credential":{"response":{"authenticatorData":"YXV0aA","clientDataJSON":"Y2xpZW50"}}}`,
		},
		{
			name:  "array with tagged binary",
			input: `{"items": [{"$b64u": "aXRlbTE"}, {"$b64u": "aXRlbTI"}]}`,
			want:  `{"items":["aXRlbTE","aXRlbTI"]}`,
		},
		{
			name:  "no tagged binary",
			input: `{"name": "test", "value": 123}`,
			want:  `{"name":"test","value":123}`,
		},
		{
			name:  "empty object",
			input: `{}`,
			want:  `{}`,
		},
		{
			name:  "mixed values",
			input: `{"name": "test", "data": {"$b64u": "dGVzdA"}, "count": 5}`,
			want:  `{"count":5,"data":"dGVzdA","name":"test"}`,
		},
		{
			name:  "realistic webauthn credential",
			input: `{"type":"public-key","id":"abc123","rawId":{"$b64u":"YWJjMTIz"},"response":{"authenticatorData":{"$b64u":"YXV0aERhdGE"},"clientDataJSON":{"$b64u":"Y2xpZW50RGF0YQ"},"signature":{"$b64u":"c2lnbmF0dXJl"}}}`,
			want:  `{"id":"abc123","rawId":"YWJjMTIz","response":{"authenticatorData":"YXV0aERhdGE","clientDataJSON":"Y2xpZW50RGF0YQ","signature":"c2lnbmF0dXJl"},"type":"public-key"}`,
		},
		{
			name:    "invalid json",
			input:   `{invalid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeJSON([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Normalize JSON for comparison (re-marshal both)
			var gotObj, wantObj interface{}
			_ = json.Unmarshal(got, &gotObj)
			_ = json.Unmarshal([]byte(tt.want), &wantObj)

			gotNorm, _ := json.Marshal(gotObj)
			wantNorm, _ := json.Marshal(wantObj)

			if string(gotNorm) != string(wantNorm) {
				t.Errorf("DecodeJSON() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestEncodeJSON(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		binaryFields map[string]bool
		want         string
	}{
		{
			name:         "encode single field",
			input:        `{"rawId": "SGVsbG8", "type": "public-key"}`,
			binaryFields: map[string]bool{"rawId": true},
			want:         `{"rawId":{"$b64u":"SGVsbG8"},"type":"public-key"}`,
		},
		{
			name:         "encode nested field",
			input:        `{"response": {"authenticatorData": "YXV0aA"}}`,
			binaryFields: map[string]bool{"response.authenticatorData": true},
			want:         `{"response":{"authenticatorData":{"$b64u":"YXV0aA"}}}`,
		},
		{
			name:         "no fields to encode",
			input:        `{"name": "test"}`,
			binaryFields: map[string]bool{},
			want:         `{"name":"test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeJSON([]byte(tt.input), tt.binaryFields)
			if err != nil {
				t.Errorf("EncodeJSON() error = %v", err)
				return
			}

			// Normalize JSON for comparison
			var gotObj, wantObj interface{}
			_ = json.Unmarshal(got, &gotObj)
			_ = json.Unmarshal([]byte(tt.want), &wantObj)

			gotNorm, _ := json.Marshal(gotObj)
			wantNorm, _ := json.Marshal(wantObj)

			if string(gotNorm) != string(wantNorm) {
				t.Errorf("EncodeJSON() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestIsTaggedBinary(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"has tagged binary", `{"data": {"$b64u": "test"}}`, true},
		{"no tagged binary", `{"data": "test"}`, false},
		{"empty", `{}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTaggedBinary([]byte(tt.input)); got != tt.want {
				t.Errorf("IsTaggedBinary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustDecodeJSON(t *testing.T) {
	// Valid JSON with tagged binary
	input := `{"rawId": {"$b64u": "SGVsbG8"}}`
	got := MustDecodeJSON([]byte(input))

	var obj map[string]interface{}
	_ = json.Unmarshal(got, &obj)

	if rawId, ok := obj["rawId"].(string); !ok || rawId != "SGVsbG8" {
		t.Errorf("MustDecodeJSON() did not decode properly")
	}

	// Invalid JSON - should return original
	invalid := []byte(`{invalid`)
	got = MustDecodeJSON(invalid)
	if string(got) != string(invalid) {
		t.Errorf("MustDecodeJSON() should return original on error")
	}
}

func TestTransformReader(t *testing.T) {
	input := `{"rawId": {"$b64u": "SGVsbG8"}}`
	reader, err := NewTransformReader([]byte(input))
	if err != nil {
		t.Fatalf("NewTransformReader() error = %v", err)
	}

	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	got := string(buf[:n])

	var obj map[string]interface{}
	json.Unmarshal([]byte(got), &obj)

	if rawId, ok := obj["rawId"].(string); !ok || rawId != "SGVsbG8" {
		t.Errorf("TransformReader.Read() did not decode properly, got %s", got)
	}
}

func TestTaggedBytes_Marshal(t *testing.T) {
	tests := []struct {
		name  string
		input TaggedBytes
		want  string
	}{
		{
			name:  "simple bytes",
			input: TaggedBytes("Hello"),
			want:  `{"$b64u":"SGVsbG8"}`,
		},
		{
			name:  "empty bytes",
			input: TaggedBytes{},
			want:  `{"$b64u":""}`,
		},
		{
			name:  "nil bytes",
			input: nil,
			want:  "null",
		},
		{
			name:  "binary data",
			input: TaggedBytes{0x00, 0x01, 0x02, 0xff},
			want:  `{"$b64u":"AAEC_w"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.input)
			if err != nil {
				t.Errorf("TaggedBytes.MarshalJSON() error = %v", err)
				return
			}
			if string(got) != tt.want {
				t.Errorf("TaggedBytes.MarshalJSON() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

func TestTaggedBytes_Unmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "tagged format",
			input: `{"$b64u":"SGVsbG8"}`,
			want:  []byte("Hello"),
		},
		{
			name:  "plain base64url",
			input: `"SGVsbG8"`,
			want:  []byte("Hello"),
		},
		{
			name:  "null",
			input: "null",
			want:  nil,
		},
		{
			name:  "binary with url-safe chars",
			input: `{"$b64u":"AAEC_w"}`,
			want:  []byte{0x00, 0x01, 0x02, 0xff},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TaggedBytes
			err := json.Unmarshal([]byte(tt.input), &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("TaggedBytes.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("TaggedBytes.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTaggedBytes_RoundTrip(t *testing.T) {
	original := TaggedBytes("Test data for round trip")
	marshaled, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var unmarshaled TaggedBytes
	err = json.Unmarshal(marshaled, &unmarshaled)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if string(original) != string(unmarshaled) {
		t.Errorf("Round trip failed: got %v, want %v", unmarshaled, original)
	}
}

// Test struct with TaggedBytes field
type testStruct struct {
	Name string      `json:"name"`
	Data TaggedBytes `json:"data"`
}

func TestTaggedBytes_InStruct(t *testing.T) {
	input := testStruct{
		Name: "test",
		Data: TaggedBytes("Hello"),
	}

	marshaled, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	expected := `{"name":"test","data":{"$b64u":"SGVsbG8"}}`
	if string(marshaled) != expected {
		t.Errorf("Marshal in struct = %s, want %s", string(marshaled), expected)
	}

	var output testStruct
	err = json.Unmarshal(marshaled, &output)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if string(output.Data) != "Hello" || output.Name != "test" {
		t.Errorf("Unmarshal in struct failed: got %v", output)
	}
}
