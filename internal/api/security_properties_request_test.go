package api

import (
	"encoding/json"
	"testing"
)

func TestSecurityPropertiesRequest_PluginIsForwardedAsAClaim(t *testing.T) {
	var req SecurityPropertiesRequest
	if err := json.Unmarshal([]byte(`{"key_storage":["software"],"plugin":"soft"}`), &req); err != nil {
		t.Fatal(err)
	}
	sp := req.toService()
	if sp.Plugin != "soft" || len(sp.KeyStorage) != 1 {
		t.Fatalf("%+v", sp)
	}
	if (*SecurityPropertiesRequest)(nil).toService() != nil {
		t.Fatal("nil request stays nil")
	}
}
