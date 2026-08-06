package statuslist

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"testing"
)

func TestEmptyCompressedList_DecodesToAllZero(t *testing.T) {
	for _, n := range []int{1, 8, 100, 10000} {
		lst, err := EmptyCompressedList(n)
		if err != nil {
			t.Fatalf("EmptyCompressedList(%d): %v", n, err)
		}

		compressed, err := base64.RawURLEncoding.DecodeString(lst)
		if err != nil {
			t.Fatalf("lst is not valid base64url: %v", err)
		}

		r := flate.NewReader(bytes.NewReader(compressed))
		defer r.Close()
		raw, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("lst does not decompress as raw DEFLATE: %v", err)
		}

		wantLen := (n + 7) / 8
		if len(raw) != wantLen {
			t.Errorf("n=%d: decompressed length = %d, want %d", n, len(raw), wantLen)
		}
		for i, b := range raw {
			if b != 0 {
				t.Errorf("n=%d: byte %d = %#x, want 0 (every status must be VALID)", n, i, b)
			}
		}
	}
}

func TestEmptyCompressedList_NonPositiveSizeDefaultsToOne(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		lst, err := EmptyCompressedList(n)
		if err != nil {
			t.Fatalf("EmptyCompressedList(%d): %v", n, err)
		}
		if lst == "" {
			t.Errorf("EmptyCompressedList(%d) returned empty string", n)
		}
	}
}
