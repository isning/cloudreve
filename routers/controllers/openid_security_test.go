package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func prepareExternal(t *testing.T, r *gin.Engine, provider int, linking bool, token string) (string, *http.Cookie) {
	t.Helper()
	w := openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]any{"provider": provider, "linking": linking}, nil, token)
	var reply struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply))
	require.Zero(t, reply.Code, w.Body.String())
	return reply.Data, w.Result().Cookies()[0]
}
func finishExternal(t *testing.T, r *gin.Engine, p *testIDP, target string, proof *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(target)
	require.NoError(t, err)
	provider := 3
	fmt.Sscanf(u.Query().Get("redirect_uri"), "https://cloudreve.example/callback/openid/%d", &provider)
	return openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": provider, "session_id": u.Query().Get("state"), "code": p.code(t, target)}, proof)
}
func responseCode(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var reply struct{ Code int }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply))
	return reply.Code
}
func changeProvider(t *testing.T, d *openidTestDep, mutate func(*oidc.Registry)) {
	t.Helper()
	registry, err := d.s.ExternalLoginProviders(context.Background())
	require.NoError(t, err)
	mutate(registry)
	raw, err := json.Marshal(registry)
	require.NoError(t, err)
	require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{oidc.SettingName: string(raw)}))
}
func nativeFixture(t *testing.T) (*gin.Engine, *openidTestDep, *testIDP, *ent.User, *auth.Token) {
	t.Helper()
	p := newTestIDP(t)
	_, d := newOpenIDFixture(t, p)
	for i := 1; i <= 3; i++ {
		_, err := d.db.Group.Create().SetName(fmt.Sprintf("Group %d", i)).SetPermissions(&boolset.BooleanSet{}).Save(context.Background())
		require.NoError(t, err)
	}
	u, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "local@example.com", PlainPassword: "local-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	d.encoder, err = hashid.New("fixture")
	require.NoError(t, err)
	d.native = auth.NewTokenAuth(d.encoder, d.s, []byte("fixture native signing key"), d.UserClient(), logging.NewConsoleLogger(logging.LevelError), d.kv, nil)
	token, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: u})
	require.NoError(t, err)
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), d.encoder, d.kv, d.s)})
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	}, middleware.CurrentUser())
	r.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	r.POST("/api/v4/session/openid", ctl.FinishOpenID)
	r.DELETE("/api/v4/session/openid/:provider_id", ctl.UnlinkOpenID)
	r.POST("/api/v4/session/token/refresh", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserRefreshToken)
	r.DELETE("/api/v4/session/token", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserSignOut)
	return r, d, p, u, token
}
func TestOpenIDRejectsInvalidProviderProofs(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*testIDP, *openidTestDep)
		message   string
	}{
		{"nonce", func(p *testIDP, _ *openidTestDep) { p.nonceOverride = "wrong" }, "nonce"},
		{"issuer", func(p *testIDP, _ *openidTestDep) { p.issuerOverride = "https://other.example" }, "validation failed"},
		{"audience", func(p *testIDP, _ *openidTestDep) { p.audienceOverride = "other-client" }, "validation failed"},
		{"expiry", func(p *testIDP, _ *openidTestDep) { p.expireOverride = true }, "validation failed"},
		{"signature", func(p *testIDP, _ *openidTestDep) { p.signatureOverride = true }, "validation failed"},
		{"access-token-hash", func(p *testIDP, _ *openidTestDep) { p.claimsExtra = map[string]any{"at_hash": "wrong"} }, "hash validation failed"},
		{"userinfo", func(p *testIDP, _ *openidTestDep) { p.userinfoOverride = "another-user" }, "userinfo subject"},
		{"userinfo-missing-subject", func(p *testIDP, _ *openidTestDep) { p.userinfoMissing = true }, "userinfo subject"},
		{"mapped-subject", func(p *testIDP, d *openidTestDep) {
			p.claimsExtra = map[string]any{"external_id": "another-user"}
			changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Config.SubMapping = "external_id" })
		}, "mapped subject"},
		{"authorized-party", func(p *testIDP, _ *openidTestDep) {
			p.audienceOverride = []string{"cloudreve", "other"}
			p.claimsExtra = map[string]any{"azp": "other"}
		}, "authorized party"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestIDP(t)
			r, d := newOpenIDFixture(t, p)
			tc.configure(p, d)
			target, proof := prepareExternal(t, r, 3, false, "")
			w := finishExternal(t, r, p, target, proof)
			require.NotZero(t, responseCode(t, w))
			require.Contains(t, w.Body.String(), tc.message)
			require.NotContains(t, w.Body.String(), "fixture-secret")
			require.NotContains(t, w.Body.String(), "fixture-access")
		})
	}
}
func TestOpenIDHotReloadRejectsPreparedState(t *testing.T) {
	p := newTestIDP(t)
	r, d := newOpenIDFixture(t, p)
	target, proof := prepareExternal(t, r, 3, false, "")
	changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Config.Scope = "offline_access" })
	w := finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "configuration changed")
}
func TestOpenIDUnlinkTombstoneAndExplicitRelink(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	w := openIDRequest(t, r, "DELETE", "/api/v4/session/openid/3", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Config.DirectSignIn = true })
	target, proof = prepareExternal(t, r, 3, false, "")
	w = finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "historical identity")
	target, proof = prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
}
func TestOpenIDCallbackIsConsumedOnceConcurrently(t *testing.T) {
	r, _, p, _, token := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	u, _ := url.Parse(target)
	code := p.code(t, target)
	var wait sync.WaitGroup
	responses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			w := openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "session_id": u.Query().Get("state"), "code": code}, proof)
			responses <- responseCode(t, w)
		}()
	}
	wait.Wait()
	close(responses)
	winners := 0
	for code := range responses {
		if code == 0 {
			winners++
		}
	}
	require.Equal(t, 1, winners)
}
func TestOpenIDLogoutUsesOriginalProviderSnapshot(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Wellknown.EndSessionEndpoint = p.server.URL + "/logout" })
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	var login struct {
		Code int
		Data struct{ Token auth.Token }
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	require.Zero(t, login.Code)
	changeProvider(t, d, func(r *oidc.Registry) { r.Providers[0].Wellknown.EndSessionEndpoint = "https://other.example/logout" })
	w = openIDRequest(t, r, "DELETE", "/api/v4/session/token", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)
	var logout struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &logout))
	require.Zero(t, logout.Code, w.Body.String())
	destination, err := url.Parse(logout.Data)
	require.NoError(t, err)
	require.Equal(t, p.server.URL+"/logout", destination.Scheme+"://"+destination.Host+destination.Path)
	require.NotEmpty(t, destination.Query().Get("id_token_hint"))
	require.Equal(t, "https://cloudreve.example", destination.Query().Get("post_logout_redirect_uri"))
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)
	require.NotZero(t, responseCode(t, w))
}
func TestOpenIDExpiredStateCannotAuthenticate(t *testing.T) {
	p := newTestIDP(t)
	r, d := newOpenIDFixture(t, p)
	now := time.Now()
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Now: func() time.Time { return now }})
	target, proof := prepareExternal(t, r, 3, false, "")
	now = now.Add(11 * time.Minute)
	w := finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "expired")
}
