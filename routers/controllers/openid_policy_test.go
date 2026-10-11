package controllers_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/stretchr/testify/require"
)

func TestOpenIDPasswordResetCompletionHonorsCurrentPolicy(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed=%t", managed), func(t *testing.T) {
			r, d, _, u, _ := nativeFixture(t)
			// A recovery capability may have been created before account policy changed.
			require.NoError(t, d.kv.Set(fmt.Sprintf("user_reset_%d", u.ID), "fixture-reset-proof", 300))
			require.NoError(t, d.db.User.UpdateOne(u).SetSSOManaged(managed).Exec(context.Background()))
			r.PATCH("/api/v4/user/reset/:id", middleware.HashID(hashid.UserID), ctl.FromJSON[usersvc.UserResetService](usersvc.UserResetParameterCtx{}), ctl.UserReset)
			w := openIDRequest(t, r, "PATCH", "/api/v4/user/reset/"+hashid.EncodeUserID(d.encoder, u.ID), map[string]string{"password": "new-recovery-password", "secret": "fixture-reset-proof"}, nil)
			if managed {
				require.NotZero(t, responseCode(t, w))
				require.Contains(t, w.Body.String(), "managed account")
			} else {
				require.Zero(t, responseCode(t, w), w.Body.String())
			}
			fresh, err := d.UserClient().GetByID(context.Background(), u.ID)
			require.NoError(t, err)
			require.Equal(t, managed, fresh.SSOManaged)
			if managed {
				require.Equal(t, u.Password, fresh.Password)
			} else {
				require.NotEqual(t, u.Password, fresh.Password)
			}
		})
	}
}

func TestOpenIDOrdinaryEmptyPasswordRemainsRecoverable(t *testing.T) {
	r, d, _, u, token := nativeFixture(t)
	require.NoError(t, d.db.User.UpdateOne(u).SetPassword("").Exec(context.Background()))
	r.GET("/api/v4/user/setting", ctl.UserSetting)
	w := openIDRequest(t, r, "GET", "/api/v4/user/setting", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), `"passwordless":true`)
	require.Contains(t, w.Body.String(), `"password_reset":true`)
	require.Contains(t, w.Body.String(), `"passkey_register":true`)
	require.NotContains(t, w.Body.String(), `"reason":"managed"`)
}

func TestOpenIDPasskeyRegistrationHonorsPolicyAtBothStages(t *testing.T) {
	r, d, _, u, token := nativeFixture(t)
	r.PUT("/api/v4/user/authn", ctl.StartRegAuthn)
	r.POST("/api/v4/user/authn", ctl.FromJSON[usersvc.FinishPasskeyRegisterService](usersvc.FinishPasskeyRegisterParameterCtx{}), ctl.FinishRegAuthn)
	r.PUT("/api/v4/session/authn", ctl.StartLoginAuthn)
	w := openIDRequest(t, r, "PUT", "/api/v4/user/authn", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	require.Contains(t, w.Body.String(), `"challenge"`)
	require.Contains(t, w.Body.String(), `"cloudreve.example"`)
	_, present := d.kv.Get(fmt.Sprintf("authn_session_%d", u.ID))
	require.True(t, present)
	require.NoError(t, d.db.User.UpdateOne(u).SetSSOManaged(true).Exec(context.Background()))
	w = openIDRequest(t, r, "POST", "/api/v4/user/authn", map[string]string{"response": "{}", "name": "Fixture key", "ua": "Fixture browser"}, nil, token.AccessToken)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "managed account")
	require.Zero(t, d.db.Passkey.Query().CountX(context.Background()))
	w = openIDRequest(t, r, "PUT", "/api/v4/user/authn", nil, nil, token.AccessToken)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "managed account")
	// Discoverable authentication remains available to ordinary accounts. This
	// exercises the real SDK and original public API, not a replacement challenge.
	w = openIDRequest(t, r, "PUT", "/api/v4/session/authn", nil, nil)
	require.Zero(t, responseCode(t, w), w.Body.String())
	require.Contains(t, w.Body.String(), `"challenge"`)
}
