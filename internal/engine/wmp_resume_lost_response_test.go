package engine

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// If the resume response is lost after the server rotated the token, the
// client retries with the OLD token: that must succeed exactly once.
func TestWMP_Resume_LostResponseRetryWithOldTokenSucceedsOnce(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, tokA, _ := createSessionFull(t, a, "owner", "t", nil)

	r1, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.Nil(t, rpcErr)
	tokB := r1.ResumptionToken // never delivered to the client

	r2, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.Nil(t, rpcErr, "retry with the old token must recover the session")
	assert.True(t, r2.Resumed)
	tokC := r2.ResumptionToken
	assert.NotEqual(t, tokB, tokC)

	// One-shot: the old token is now spent, and so is the undelivered one.
	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.NotNil(t, rpcErr)
	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, tokB, ""))
	require.NotNil(t, rpcErr, "the lost successor must be retired by the retry")

	// The token from the successful retry works.
	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, tokC, ""))
	require.Nil(t, rpcErr)
}

// Once the new token has been used the client demonstrably has it, so the
// old token must stop working.
func TestWMP_Resume_OldTokenDeadAfterNewTokenUsed(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, tokA, _ := createSessionFull(t, a, "owner", "t", nil)

	r1, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.Nil(t, rpcErr)
	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, r1.ResumptionToken, ""))
	require.Nil(t, rpcErr)

	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.NotNil(t, rpcErr, "old token must not work once its successor was used")
}

// The grace window is bounded.
func TestWMP_Resume_OldTokenDeadAfterGraceWindow(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, tokA, _ := createSessionFull(t, a, "owner", "t", nil)

	_, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.Nil(t, rpcErr)

	a.mu.Lock()
	e := a.resumptionTokens[tokA]
	require.NotNil(t, e, "consumed token must be retained for the grace window")
	assert.True(t, e.expiresAt.Before(time.Now().Add(resumptionGraceWindow+time.Second)))
	e.expiresAt = time.Now().Add(-time.Second)
	a.mu.Unlock()

	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.NotNil(t, rpcErr)
}

// Another user can never redeem a token, fresh or in its grace window, and
// the attempt must not burn the owner's retry.
func TestWMP_Resume_GraceTokenNotUsableByOtherUser(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, tokA, _ := createSessionFull(t, a, "owner", "t", nil)

	_, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.Nil(t, rpcErr)

	_, rpcErr = doResume(t, a, "attacker", "t", resumeBody(sid, tokA, ""))
	require.NotNil(t, rpcErr)

	_, rpcErr = doResume(t, a, "owner", "t", resumeBody(sid, tokA, ""))
	require.Nil(t, rpcErr, "owner's retry must survive a rejected foreign attempt")
}

// Two resumes racing on one token: at most the single permitted retry succeeds; a third is rejected.
func TestWMP_Resume_OldTokenAtMostTwiceTotal(t *testing.T) {
	a, m := testWMPAdapter()
	defer cleanupWMP(a, m)
	sid, tokA, _ := createSessionFull(t, a, "owner", "t", nil)

	ok := 0
	for i := 0; i < 4; i++ {
		if _, rpcErr := doResume(t, a, "owner", "t", resumeBody(sid, tokA, "")); rpcErr == nil {
			ok++
		}
	}
	assert.Equal(t, 2, ok, "original use plus exactly one lost-response retry")
}
