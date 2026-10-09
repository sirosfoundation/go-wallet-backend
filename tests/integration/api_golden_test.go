package integration

import (
	"net/http"
	"testing"
)

func TestGoldenWebAuthnRegistrationBegin(t *testing.T) {
	tests := []GoldenTest{
		{
			Name: "registration_begin",
			Request: func(h *TestHarness) *Response {
				return h.POST("/auth/passkey/register/begin", map[string]interface{}{})
			},
			Filename: "webauthn_registration_begin.json",
		},
		{
			Name: "login_begin",
			Request: func(h *TestHarness) *Response {
				return h.POST("/auth/passkey/login/begin", map[string]interface{}{})
			},
			Filename: "webauthn_login_begin.json",
		},
	}

	RunGoldenTests(t, tests)
}

func TestGoldenStatus(t *testing.T) {
	tests := []GoldenTest{
		{
			Name: "status",
			Request: func(h *TestHarness) *Response {
				resp := h.GET("/status")
				resp.Status(http.StatusOK)
				return resp
			},
			Filename: "status.json",
		},
	}

	RunGoldenTests(t, tests)
}
