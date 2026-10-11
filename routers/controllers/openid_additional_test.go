package controllers_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/openidtransaction"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestOpenIDAdditionalScopesAndFixedExchange(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	changeProvider(t, d, func(registry *oidc.Registry) {
		registry.Providers[0].Config.Scope = " profile, offline_access, email, api:read, api:read "
	})
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	u, err := url.Parse(target)
	require.NoError(t, err)
	require.Equal(t, "openid email profile offline_access api:read", u.Query().Get("scope"))
	code := p.code(t, target)
	w := openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "code": code, "session_id": u.Query().Get("state"), "redirect_uri": "https://attacker.example/callback", "code_verifier": "attacker-verifier", "user_id": 9999}, proof)
	require.Zero(t, responseCode(t, w), w.Body.String())
	p.mu.Lock()
	defer p.mu.Unlock()
	require.Len(t, p.exchanges, 1)
	require.Equal(t, "https://cloudreve.example/callback/openid/3", p.exchanges[0].Get("redirect_uri"))
	require.NotEqual(t, "attacker-verifier", p.exchanges[0].Get("code_verifier"))
}

func TestOpenIDLinkingRejectsAnotherActiveAccount(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	other, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "other@example.com", PlainPassword: "other-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	otherToken, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: other})
	require.NoError(t, err)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	u, _ := url.Parse(target)
	body := map[string]any{"provider_id": 3, "code": p.code(t, target), "session_id": u.Query().Get("state"), "user_id": other.ID}
	w := openIDRequest(t, r, "POST", "/api/v4/session/openid", body, proof, otherToken.AccessToken)
	require.NotZero(t, responseCode(t, w))
	require.Zero(t, d.db.ExternalIdentity.Query().CountX(context.Background()))
	// A conflicting bearer cannot burn the original browser transaction.
	w = openIDRequest(t, r, "POST", "/api/v4/session/openid", body, proof)
	require.Zero(t, responseCode(t, w), w.Body.String())
}

func TestOpenIDManagedConcurrentUnlinkProtectsLastUsableIdentity(t *testing.T) {
	r, d, p, u, token := nativeFixture(t)
	changeProvider(t, d, func(registry *oidc.Registry) {
		second := registry.Providers[0]
		second.ID = 4
		registry.Providers = append(registry.Providers, second)
		registry.NextID = 5
	})
	for _, id := range []int{3, 4} {
		target, proof := prepareExternal(t, r, id, true, token.AccessToken)
		require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	}
	require.NoError(t, d.db.User.UpdateOne(u).SetSSOManaged(true).Exec(context.Background()))
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	for _, id := range []int{3, 4} {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			path := "/api/v4/session/openid/3"
			if id == 4 {
				path = "/api/v4/session/openid/4"
			}
			responses <- openIDRequest(t, r, "DELETE", path, nil, nil, token.AccessToken)
		}(id)
	}
	wg.Wait()
	close(responses)
	winners := 0
	for w := range responses {
		if responseCode(t, w) == 0 {
			winners++
		}
	}
	require.Equal(t, 1, winners)
	bindings, err := d.o.View(context.Background(), u.ID)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
}

func TestOpenIDMFAFailuresCannotEstablishSession(t *testing.T) {
	for _, failure := range []string{"attempts", "expired", "disabled", "deleted", "provider-disabled", "damaged"} {
		t.Run(failure, func(t *testing.T) {
			r, d, p, u, token := nativeFixture(t)
			adminToken := token
			if failure == "deleted" {
				var err error
				u, err = d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "pending-delete@example.com", PlainPassword: "fixture-password", Status: entuser.StatusActive, GroupID: 2})
				require.NoError(t, err)
				token, err = d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: u})
				require.NoError(t, err)
			}
			target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
			require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
			secret := "JBSWY3DPEHPK3PXP"
			require.NoError(t, d.db.User.UpdateOne(u).SetTwoFactorSecret(secret).Exec(context.Background()))
			target, proof = prepareExternal(t, r, 3, false, "")
			w := finishExternal(t, r, p, target, proof)
			var challenge struct {
				Code int
				Data string
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
			require.Equal(t, 203, challenge.Code)
			proof = w.Result().Cookies()[0]
			r.POST("/api/v4/session/token/2fa", ctl.FromJSON[usersvc.OtpValidationService](usersvc.OtpValidationParameterCtx{}), ctl.UserLogin2FAValidation, ctl.UserIssueToken)
			otp, err := totp.GenerateCode(secret, time.Now())
			require.NoError(t, err)
			switch failure {
			case "attempts":
				for i := 0; i < 5; i++ {
					require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/token/2fa", map[string]string{"otp": "wrong", "session_id": challenge.Data}, proof)))
				}
			case "expired":
				require.NoError(t, d.db.OpenIDTransaction.Update().Where(openidtransaction.KindEQ(openidtransaction.KindPendingMfa)).SetExpiresAt(time.Now().UTC().Add(-time.Minute)).Exec(context.Background()))
			case "disabled":
				require.NoError(t, d.db.User.UpdateOne(u).SetStatus(entuser.StatusManualBanned).Exec(context.Background()))
			case "deleted":
				r.DELETE("/api/v4/admin/user", ctl.FromJSON[admin.BatchUserService](admin.BatchUserParamCtx{}), ctl.AdminDeleteUser)
				w = openIDRequest(t, r, "DELETE", "/api/v4/admin/user", map[string]any{"ids": []int{u.ID}}, nil, adminToken.AccessToken)
				require.Zero(t, responseCode(t, w), w.Body.String())
			case "provider-disabled":
				changeProvider(t, d, func(registry *oidc.Registry) { registry.Providers[0].Enabled = false })
			case "damaged":
				require.NoError(t, d.db.OpenIDTransaction.Update().Where(openidtransaction.KindEQ(openidtransaction.KindPendingMfa)).SetPayload([]byte("damaged")).Exec(context.Background()))
			}
			w = openIDRequest(t, r, "POST", "/api/v4/session/token/2fa", map[string]string{"otp": otp, "session_id": challenge.Data}, proof)
			require.NotZero(t, responseCode(t, w))
			require.NotContains(t, w.Body.String(), "access_token")
			require.Zero(t, d.db.OpenIDSession.Query().CountX(context.Background()))
		})
	}
}
