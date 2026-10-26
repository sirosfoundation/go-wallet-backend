package domain

import "testing"

func TestAppAttestKeyRecord_BelongsTo(t *testing.T) {
	u1, u2 := UserIDFromString("u1"), UserIDFromString("u2")
	withUser := &AppAttestKeyRecord{TenantID: "t", UserID: &u1}
	noUser := &AppAttestKeyRecord{TenantID: "t"}
	cases := []struct {
		name string
		rec  *AppAttestKeyRecord
		ten  TenantID
		user *UserID
		want bool
	}{
		{"same user", withUser, "t", &u1, true},
		{"other user", withUser, "t", &u2, false},
		{"no caller user for user key", withUser, "t", nil, false},
		{"other tenant", withUser, "x", &u1, false},
		{"unbound key, unbound caller", noUser, "t", nil, true},
		{"unbound key, user caller", noUser, "t", &u1, false},
	}
	for _, c := range cases {
		if got := c.rec.BelongsTo(c.ten, c.user); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestAppAttestKeyRecord_ActiveAndHomeEligibility(t *testing.T) {
	if (&AppAttestKeyRecord{}).IsActive() {
		t.Error("empty status must not be active")
	}
	if !(&AppAttestKeyRecord{Status: AppAttestKeyActive}).IsActive() {
		t.Error("active must be active")
	}
	if (&AppAttestKeyRecord{Status: AppAttestKeyRevoked}).IsActive() {
		t.Error("revoked must not be active")
	}
	if !(&AppAttestKeyRecord{Environment: AppAttestProduction, ChainVerified: true}).VerifiedHomeEligible() {
		t.Error("production + chain verified is eligible")
	}
	for _, r := range []*AppAttestKeyRecord{
		{Environment: AppAttestDevelopment, ChainVerified: true},
		{Environment: AppAttestProduction, ChainVerified: false},
		{ChainVerified: true},
	} {
		if r.VerifiedHomeEligible() {
			t.Errorf("%+v must not be eligible", r)
		}
	}
}
