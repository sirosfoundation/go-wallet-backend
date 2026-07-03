package as

import (
	"testing"
)

func TestBuildTokenQuery_AllFields(t *testing.T) {
	q := BuildTokenQuery("user-1", "backend-api", "tenant-42", TAC("rw"), "urn:siros:acr:passkey")
	// Keys should be sorted: acr, aud, sub, tac, tenant_id
	expected := "(5:token (3:acr 21:urn:siros:acr:passkey) (3:aud 11:backend-api) (3:sub 6:user-1) (3:tac 2:rw) (9:tenant_id 9:tenant-42))"
	if q != expected {
		t.Errorf("unexpected query:\n  got:  %s\n  want: %s", q, expected)
	}
}

func TestBuildTokenQuery_MinimalFields(t *testing.T) {
	q := BuildTokenQuery("user-1", "api", "", TAC("r"), "")
	expected := "(5:token (3:aud 3:api) (3:sub 6:user-1) (3:tac 1:r))"
	if q != expected {
		t.Errorf("unexpected query:\n  got:  %s\n  want: %s", q, expected)
	}
}

func TestBuildTokenQuery_Empty(t *testing.T) {
	q := BuildTokenQuery("", "", "", "", "")
	if q != "(5:token)" {
		t.Errorf("expected (5:token), got %s", q)
	}
}

func TestBuildTokenQuery_Deterministic(t *testing.T) {
	q1 := BuildTokenQuery("alice", "svc", "t1", TAC("rwl"), "acr:foo")
	q2 := BuildTokenQuery("alice", "svc", "t1", TAC("rwl"), "acr:foo")
	if q1 != q2 {
		t.Error("BuildTokenQuery is not deterministic")
	}
}
