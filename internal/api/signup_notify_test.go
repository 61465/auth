package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/mailer/mockclient"
	"github.com/supabase/auth/internal/models"
)

// TestSignup_RepeatOnConfirmedUser_TriggersRecoveryMail covers the
// behavior proposed on supabase/auth#1517: when a client submits a
// signup for an email that already belongs to a confirmed user, the
// public response stays identical to a brand-new signup (anti-
// enumeration), but the real account owner receives a recovery mail so
// they can regain access instead of waiting for a confirmation email
// that never arrives.
func TestSignup_RepeatOnConfirmedUser_TriggersRecoveryMail(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)
	defer api.db.Close()

	models.TruncateAll(api.db)
	require.True(t, config.Mailer.SecureSignupNotifyEnabled,
		"SecureSignupNotifyEnabled must default to true")

	const email = "repeat-signup@example.com"

	seed, err := models.NewUser("", email, "first-password", config.JWT.Aud, nil)
	require.NoError(t, err)
	require.NoError(t, api.db.Create(seed))
	require.NoError(t, seed.Confirm(api.db))

	var body bytes.Buffer
	require.NoError(t, json.NewEncoder(&body).Encode(map[string]interface{}{
		"email":    email,
		"password": "second-password",
	}))
	req := httptest.NewRequest(http.MethodPost, "/signup", &body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code,
		"public response must match a brand-new signup to avoid leaking existence")

	response := models.User{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.NotEqual(t, seed.ID, response.ID,
		"response must carry a sanitized random ID, never the real user id")
	assert.Equal(t, email, response.GetEmail())

	require.Len(t, mockMailer.RecoveryMailCalls, 1,
		"a recovery mail must be sent to the real owner on repeat signup")
	assert.Equal(t, email, mockMailer.RecoveryMailCalls[0].User.GetEmail())
	assert.Empty(t, mockMailer.ConfirmationMailCalls,
		"no confirmation mail should be sent on repeat signup of a confirmed user")
}

// TestSignup_RepeatOnConfirmedUser_FeatureFlagOff asserts that operators
// who opt out keep the pre-change behavior: the sanitized response is
// still returned, but no recovery mail is dispatched.
func TestSignup_RepeatOnConfirmedUser_FeatureFlagOff(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)
	defer api.db.Close()

	config.Mailer.SecureSignupNotifyEnabled = false
	models.TruncateAll(api.db)

	const email = "flag-off@example.com"

	seed, err := models.NewUser("", email, "pw", config.JWT.Aud, nil)
	require.NoError(t, err)
	require.NoError(t, api.db.Create(seed))
	require.NoError(t, seed.Confirm(api.db))

	var body bytes.Buffer
	require.NoError(t, json.NewEncoder(&body).Encode(map[string]interface{}{
		"email":    email,
		"password": "pw2",
	}))
	req := httptest.NewRequest(http.MethodPost, "/signup", &body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, mockMailer.RecoveryMailCalls,
		"recovery mail must not be sent when the feature flag is off")
}

// TestSignup_RepeatOnUnconfirmedUser_DoesNotSendRecovery asserts that
// the recovery-mail branch is scoped to confirmed users only; the
// pre-existing re-send-confirmation flow still owns the unconfirmed
// case and must not be duplicated.
func TestSignup_RepeatOnUnconfirmedUser_DoesNotSendRecovery(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, cfg, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)
	defer api.db.Close()

	models.TruncateAll(api.db)

	const email = "unconfirmed@example.com"

	seed, err := models.NewUser("", email, "pw", cfg.JWT.Aud, nil)
	require.NoError(t, err)
	require.NoError(t, api.db.Create(seed))
	// deliberately not confirming

	var body bytes.Buffer
	require.NoError(t, json.NewEncoder(&body).Encode(map[string]interface{}{
		"email":    email,
		"password": "pw2",
	}))
	req := httptest.NewRequest(http.MethodPost, "/signup", &body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, mockMailer.RecoveryMailCalls,
		"recovery mail must not fire for unconfirmed accounts")
}

