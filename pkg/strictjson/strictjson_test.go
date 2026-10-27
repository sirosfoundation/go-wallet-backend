package strictjson

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The decoding step refuses every ambiguity with ErrAmbiguous and reads
// everything else. Each row is one way two decoders could see different
// documents.
func TestDecodeStrict_Ambiguity(t *testing.T) {
	type doc struct {
		Type    string `json:"type"`
		Opening string `json:"opening"`
		Sub     struct {
			Path []string `json:"path"`
		} `json:"sub"`
	}
	for name, in := range map[string]string{
		"repeated member":                `{"type":"a","type":"b"}`,
		"repeated, null last":            `{"opening":"S","opening":null}`,
		"repeated nested":                `{"sub":{"path":["a"],"path":null}}`,
		"repeated in an array element":   `{"x":[{"a":1},{"b":1,"b":2}]}`,
		"case-variant twin":              `{"type":"a","TYPE":"b"}`,
		"case-variant twin, other order": `{"Type":"b","type":"a"}`,
		"long s look-alike twin":         `{"auxiliary_data_supported":1,"auxiliary_data_ſupported":2}`,
		"protocol member, other case":    `{"Type":"a"}`,
		"protocol member, upper case":    `{"OPENING":"S"}`,
		"protocol member, nested":        `{"x":[{"y":{"Opening":"S"}}]}`,
		"trailing value":                 `{"type":"a"} {"type":"b"}`,
		"trailing scalar":                `{"type":"a"} 1`,
		"trailing garbage":               `{"type":"a"} x`,
		"trailing after scalar":          `1 2`,
	} {
		t.Run(name, func(t *testing.T) {
			var d any
			err := Decode([]byte(in), &d)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrAmbiguous)
			assert.NotContains(t, err.Error(), "S\"")
		})
	}

	// Syntax and type errors are errors, but not ambiguity.
	for name, in := range map[string]string{
		"empty":         ``,
		"truncated":     `{"type":"a"`,
		"wrong type":    `{"type":1}`,
		"not an object": `[1]`,
	} {
		t.Run(name, func(t *testing.T) {
			var d doc
			err := Decode([]byte(in), &d)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrAmbiguous)
		})
	}

	// Unambiguous documents are read: other claim names, equal names in
	// different objects, whitespace around the value.
	var d doc
	// A number a float cannot hold is still valid JSON.
	require.NoError(t, Decode([]byte(`{"n":1e400,"type":"a"}`), &d))
	require.NoError(t, Decode([]byte(` {"type":"a","other":{"type":"b"},"Another":null,"sub":{"path":["p"]}} `), &d))
	assert.Equal(t, "a", d.Type)
	assert.Equal(t, []string{"p"}, d.Sub.Path)
}

// The depth limit is what lets a configuration's own member names be checked
// without judging the free-form content below them.
func TestCheckUnambiguous_Depth(t *testing.T) {
	const in = `{"a":{"b":1,"b":2},"c":1}`
	require.Error(t, Check([]byte(in), -1))
	require.NoError(t, Check([]byte(in), 1))
	require.Error(t, Check([]byte(`{"c":1,"C":2}`), 1))
	require.NoError(t, Check([]byte(strings.Repeat(`[`, 3)+strings.Repeat(`]`, 3)), 1))
}

// Validation is linear in the number of names: an object of 200,000 distinct
// names is checked in well under a second (a scan of every earlier name would
// need some 2e10 comparisons).
func TestCheckUnambiguous_ManyNamesIsLinear(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 200000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%d":1`, i)
	}
	b.WriteString("}")
	start := time.Now()
	require.NoError(t, Check([]byte(b.String()), -1))
	assert.Less(t, time.Since(start), 5*time.Second)
}

// Depth tracking is constant work per token: walking a deeply nested document
// costs about what walking a flat one with as many members does. The comparison
// is relative so that a slow machine cannot fail it.
func TestCheckUnambiguous_DeepAndWideIsLinear(t *testing.T) {
	const depth, width = 5000, 400000
	doc := func(depth int) []byte {
		var b strings.Builder
		b.WriteString(strings.Repeat(`{"a":`, depth))
		b.WriteString("{")
		for i := 0; i < width; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"k%d":1`, i)
		}
		b.WriteString("}")
		b.WriteString(strings.Repeat(`}`, depth))
		return []byte(b.String())
	}
	flat, deep := doc(1), doc(depth)
	best := func(d []byte) time.Duration {
		min := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			start := time.Now()
			require.NoError(t, Check(d, 1))
			if el := time.Since(start); el < min {
				min = el
			}
		}
		return min
	}
	assert.Less(t, best(deep), 3*best(flat))
}

// Each rule refuses exactly what it names; a repeated name is refused by all.
func TestWalk_Rules(t *testing.T) {
	for name, tc := range map[string]struct {
		in      string
		rules   Rules
		refused bool
	}{
		"repeat, no rules":                {`{"a":1,"a":2}`, 0, true},
		"case variants, no rules":         {`{"a":1,"A":2}`, 0, false},
		"case variants, FoldCase":         {`{"a":1,"A":2}`, FoldCase, true},
		"protocol name variant, FoldCase": {`{"Type":1}`, FoldCase, false},
		"protocol name variant, Protocol": {`{"Type":1}`, ProtocolCase, true},
		"protocol name exact, Protocol":   {`{"type":1}`, ProtocolCase, false},
		"unrelated names, All":            {`{"x":1,"y":{"z":2}}`, All, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := Walk([]byte(tc.in), -1, tc.rules)
			if tc.refused {
				require.ErrorIs(t, err, ErrAmbiguous)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// The walk is a validator: empty and cut-off documents are errors, not ambiguity.
func TestWalk_EmptyAndTruncatedAreSyntaxErrors(t *testing.T) {
	for name, in := range map[string]string{
		"empty": ``, "blank": `  `, "open object": `{"a":1`, "open array": `[1`,
		"open nested": `{"a":{"b":[1,2}`, "key without value": `{"a":`,
	} {
		t.Run(name, func(t *testing.T) {
			err := Check([]byte(in), -1)
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrAmbiguous)
		})
	}
	require.NoError(t, Check([]byte(`1`), -1))
	require.NoError(t, Check([]byte(`{"a":[1]}`), -1))
}
