package authzen

import (
	"testing"

	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
)

// The PDP response context - verifier_ids included - survives the conversion
// to the wallet's response type as JSON, and is absent when there is none.
func TestFromAuthZENResponse_PreservesContext(t *testing.T) {
	e := &Evaluator{}
	resp := e.fromAuthZENResponse(&gotrust.EvaluationResponse{Decision: true, Context: &gotrust.EvaluationResponseContext{
		VerifierIDs: []gotrust.VerifierID{{Type: "x509_san_dns", ID: "rp.example.com", Basis: "client-id-binding"}},
	}})
	assert.JSONEq(t, `{"verifier_ids":[{"verifier_id_type":"x509_san_dns","verifier_id":"rp.example.com","basis":"client-id-binding"}]}`, string(resp.Context))

	assert.Nil(t, e.fromAuthZENResponse(&gotrust.EvaluationResponse{Decision: true}).Context)
	assert.Nil(t, e.fromAuthZENResponse(&gotrust.EvaluationResponse{Decision: true, Context: &gotrust.EvaluationResponseContext{}}).Context)
}
