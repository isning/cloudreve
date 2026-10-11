package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/stretchr/testify/require"
)

func TestOpenIDProviderIdentifierIsRequiredAndExplicitZeroIsValid(t *testing.T) {
	r, d, p, account, local := nativeFixture(t)
	changeProvider(t, d, func(registry *oidc.Registry) {
		registry.Providers[0].ID = 0
	})
	invalid := []struct {
		name    string
		present bool
		value   any
	}{
		{name: "missing"},
		{name: "null", present: true},
		{name: "negative", present: true, value: -1},
	}
	for _, test := range invalid {
		t.Run("prepare-"+test.name, func(t *testing.T) {
			body := map[string]any{"linking": true}
			if test.present {
				body["provider"] = test.value
			}
			w := openIDRequest(t, r, "PUT", "/api/v4/session/openid", body, nil, local.AccessToken)
			require.NotZero(t, responseCode(t, w))
			require.Zero(t, d.db.OpenIDTransaction.Query().CountX(context.Background()))
		})
	}
	target, proof := prepareExternal(t, r, 0, true, local.AccessToken)
	u, err := url.Parse(target)
	require.NoError(t, err)
	code := p.code(t, target)
	for _, test := range invalid {
		t.Run("finish-"+test.name, func(t *testing.T) {
			body := map[string]any{"code": code, "session_id": u.Query().Get("state")}
			if test.present {
				body["provider_id"] = test.value
			}
			w := openIDRequest(t, r, "POST", "/api/v4/session/openid", body, proof)
			require.NotZero(t, responseCode(t, w))
			require.Zero(t, d.db.ExternalIdentity.Query().CountX(context.Background()))
		})
	}
	w := openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 0, "code": code, "session_id": u.Query().Get("state")}, proof)
	require.Zero(t, responseCode(t, w))
	bindings, err := d.o.View(context.Background(), account.ID)
	require.NoError(t, err)
	require.Len(t, bindings, 1)
	require.Zero(t, bindings[0].Provider)
}

func TestOpenIDConcurrentJITAcrossProcessesPreservesOneAccount(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		name := "new-account"
		if conflict {
			name = "existing-email"
		}
		t.Run(name, func(t *testing.T) {
			r, d, p, local, _ := nativeFixture(t)
			local, err := d.db.User.Get(context.Background(), local.ID)
			require.NoError(t, err)
			if conflict {
				p.email = local.Email
			}
			// Synchronize only the external network fixture. Both processes retain
			// independent Ent pools, runtimes, native authentication and caches.
			arrived := make(chan struct{}, 2)
			release := make(chan struct{})
			var releaseOnce sync.Once
			profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				arrived <- struct{}{}
				select {
				case <-release:
					p.server.Config.Handler.ServeHTTP(w, req)
				case <-req.Context().Done():
				}
			}))
			t.Cleanup(profile.Close)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			changeProvider(t, d, func(registry *oidc.Registry) {
				registry.Providers[0].Config.DirectSignIn = true
				registry.Providers[0].Wellknown.UserinfoEndpoint = profile.URL + "/userinfo"
			})
			server := httptest.NewServer(r)
			t.Cleanup(server.Close)
			other := independentProcess(t, d)
			responses := make(chan *httptest.ResponseRecorder, 2)
			for _, endpoint := range []string{server.URL, other} {
				target, proof := prepareExternal(t, r, 3, false, "")
				u, err := url.Parse(target)
				require.NoError(t, err)
				body := map[string]any{"provider_id": 3, "code": p.code(t, target), "session_id": u.Query().Get("state")}
				go func(endpoint string, proof *http.Cookie, body map[string]any) {
					responses <- processRequest(t, endpoint, "POST", "/api/v4/session/openid", body, proof)
				}(endpoint, proof, body)
			}
			for range 2 {
				select {
				case <-arrived:
				case <-time.After(5 * time.Second):
					releaseOnce.Do(func() { close(release) })
					t.Fatal("both independent callbacks did not reach the provider profile boundary")
				}
			}
			releaseOnce.Do(func() { close(release) })
			var logins []auth.Token
			for range 2 {
				var response *httptest.ResponseRecorder
				select {
				case response = <-responses:
				case <-time.After(15 * time.Second):
					t.Fatal("concurrent callback did not complete")
				}
				if responseCode(t, response) != 0 {
					require.NotContains(t, response.Body.String(), "access_token")
					require.NotContains(t, response.Body.String(), "refresh_token")
					continue
				}
				var result struct{ Data struct{ Token auth.Token } }
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
				logins = append(logins, result.Data.Token)
			}
			ctx := context.Background()
			unchanged, err := d.db.User.Get(ctx, local.ID)
			require.NoError(t, err)
			require.Equal(t, local.Password, unchanged.Password)
			require.Equal(t, local.GroupUsers, unchanged.GroupUsers)
			require.False(t, unchanged.SSOManaged)
			if conflict {
				require.Empty(t, logins)
				require.Equal(t, 1, d.db.User.Query().CountX(ctx))
				require.Zero(t, d.db.ExternalIdentity.Query().CountX(ctx))
				require.Zero(t, d.db.OpenIDSession.Query().CountX(ctx))
				return
			}
			require.NotEmpty(t, logins)
			require.Equal(t, 2, d.db.User.Query().CountX(ctx), "a losing JIT transaction must not leave an orphan user")
			identity := d.db.ExternalIdentity.Query().OnlyX(ctx)
			require.NotNil(t, identity.UserID)
			require.NotEqual(t, local.ID, *identity.UserID)
			created, err := d.db.User.Get(ctx, *identity.UserID)
			require.NoError(t, err)
			require.Equal(t, p.email, created.Email)
			require.True(t, created.SSOManaged)
			require.Empty(t, created.Password)
			require.Equal(t, 2, created.GroupUsers, "concurrent onboarding must not elevate privileges")
			for _, token := range logins {
				claims, err := d.native.Claims(ctx, token.RefreshToken)
				require.NoError(t, err)
				require.Equal(t, hashid.EncodeUserID(d.encoder, created.ID), claims.Subject)
				require.Equal(t, "openid", claims.SessionSource)
			}
		})
	}
}
