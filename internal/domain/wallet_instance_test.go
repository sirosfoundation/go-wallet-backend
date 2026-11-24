package domain

import (
	"errors"
	"testing"
)

func TestValidateStatusTransition_RevokeSourceStates(t *testing.T) {
	cases := []struct {
		current InstanceStatus
		wantErr bool
	}{
		{InstanceStatusActive, false},
		{InstanceStatusLegacySuspended, false},
		{InstanceStatusRevoked, false}, // same-state no-op
		{InstanceStatus("bogus"), true},
		{InstanceStatus(""), true},
		{InstanceStatus("REVOKED "), true},
	}
	for _, c := range cases {
		err := ValidateStatusTransition(c.current, InstanceStatusRevoked)
		if c.wantErr != (err != nil) {
			t.Errorf("%q -> revoked: err=%v wantErr=%v", c.current, err, c.wantErr)
		}
		if c.wantErr && !errors.Is(err, ErrInvalidStatusTransition) {
			t.Errorf("%q -> revoked: err=%v, want ErrInvalidStatusTransition", c.current, err)
		}
	}
	if err := ValidateStatusTransition(InstanceStatusRevoked, InstanceStatusActive); err == nil {
		t.Error("revoked -> active must be refused")
	}
}

func TestRevocableStatuses(t *testing.T) {
	got := RevocableStatuses()
	if len(got) != 2 || got[0] != InstanceStatusActive || got[1] != InstanceStatusLegacySuspended {
		t.Fatalf("RevocableStatuses() = %v", got)
	}
}
