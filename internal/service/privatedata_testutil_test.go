package service

import (
	"encoding/base64"
	"encoding/json"
)

// testCredID returns a stored-format (base64url, no padding) credential ID
// derived from a label.
func testCredID(label string) string {
	return base64.RawURLEncoding.EncodeToString([]byte("cred-" + label))
}

// testPrivateDataContainer builds a privatedata container
// {mainKey, prfKeys[], jwe} with one prfKeys entry per stored-format
// credential ID. Only the fields the ownership check reads are meaningful.
func testPrivateDataContainer(credentialIDs ...string) []byte {
	prfKeys := make([]map[string]any, 0, len(credentialIDs))
	for _, id := range credentialIDs {
		prfKeys = append(prfKeys, map[string]any{
			"credentialId": map[string]string{"$b64u": id},
			"prfSalt":      map[string]string{"$b64u": "AAAA"},
		})
	}
	b, err := json.Marshal(map[string]any{
		"mainKey": map[string]any{},
		"prfKeys": prfKeys,
		"jwe":     "a.b.c.d.e",
	})
	if err != nil {
		panic(err)
	}
	return b
}
