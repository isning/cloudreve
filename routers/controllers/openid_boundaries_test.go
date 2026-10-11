package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent/openidtransaction"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestOpenIDEncryptedPurposesCannotBeInterchanged(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	session, err := d.db.OpenIDSession.Query().Only(context.Background())
	require.NoError(t, err)
	target, proof = prepareExternal(t, r, 3, false, "")
	require.NoError(t, d.db.OpenIDTransaction.Update().Where(openidtransaction.Consumed(false)).SetPayload(session.Payload).Exec(context.Background()))
	w := finishExternal(t, r, p, target, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "authentication material")
	require.NotContains(t, w.Body.String(), "access_token")
}

func TestOpenIDEmptyEncryptionKeyFailsClosedWithoutBlockingNativeRefresh(t *testing.T) {
	r, d, p, _, local := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, local.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	var login struct{ Data struct{ Token auth.Token } }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	require.Zero(t, responseCode(t, w))
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), d.encoder, d.kv, d.s)})
	before := d.db.OpenIDTransaction.Query().CountX(context.Background())
	w = openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]int{"provider": 3}, nil)
	require.NotZero(t, responseCode(t, w))
	require.Equal(t, before, d.db.OpenIDTransaction.Query().CountX(context.Background()))
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)
	require.NotZero(t, responseCode(t, w))
	require.NotContains(t, w.Body.String(), "access_token")
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": local.RefreshToken}, nil)
	require.Zero(t, responseCode(t, w), w.Body.String())
}

func TestOpenIDEnvironmentPriorityUsesEffectiveConfiguration(t *testing.T) {
	r, d, p, _, token := nativeFixture(t)
	registry, err := d.s.ExternalLoginProviders(context.Background())
	require.NoError(t, err)
	raw, err := json.Marshal(registry)
	require.NoError(t, err)
	t.Setenv(setting.EnvSettingOverwritePrefix+oidc.SettingName, string(raw))
	d.s = setting.NewProvider(setting.NewEnvOverrideStore(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)), &authenticationLog{}))
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), d.encoder, d.kv, d.s)})
	target, proof := prepareExternal(t, r, 3, true, token.AccessToken)
	registry.Providers[0].Enabled = false
	raw, err = json.Marshal(registry)
	require.NoError(t, err)
	require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{oidc.SettingName: string(raw)}))
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
}

func TestOpenIDPrivilegedEndpointsEnforcePermissions(t *testing.T) {
	_, d, p, u, token := nativeFixture(t)
	permissions := &boolset.BooleanSet{}
	boolset.Set(types.GroupPermissionIsAdmin, true, permissions)
	require.NoError(t, d.db.Group.UpdateOneID(1).SetPermissions(permissions).Exec(context.Background()))
	require.NoError(t, d.db.User.UpdateOne(u).SetSSOManaged(true).Exec(context.Background()))
	limited, err := d.native.Issue(context.Background(), &auth.IssueTokenArgs{User: u, ClientID: "limited-client", Scopes: []string{types.ScopeAdminRead}})
	require.NoError(t, err)
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	}, middleware.CurrentUser())
	r.PUT("/api/v4/session/openid", middleware.RequiredScopes(types.ScopeUserSecurityInfoWrite), ctl.BeginOpenID)
	protected := r.Group("/api/v4/admin", middleware.LoginRequired(), middleware.IsAdmin(), middleware.RequiredScopes(types.ScopeAdminRead))
	protected.GET("/tool/oidc", middleware.RequiredScopes(types.ScopeAdminWrite), ctl.DiscoverOpenID)
	protected.GET("/tool/oidc/callback/:provider_id", middleware.RequiredScopes(types.ScopeAdminWrite), ctl.OpenIDCallbackURI)
	protected.POST("/user/:id/release-managed", middleware.RequiredScopes(types.ScopeAdminWrite), ctl.ReleaseManagedAccount)
	endpoint := "/api/v4/admin/tool/oidc?endpoint=" + url.QueryEscape(p.server.URL+"/oidc/.well-known/openid-configuration")
	for _, bearer := range []string{"", limited.AccessToken} {
		require.NotZero(t, responseCode(t, openIDRequest(t, r, "GET", endpoint, nil, nil, bearer)))
		require.NotZero(t, responseCode(t, openIDRequest(t, r, "GET", "/api/v4/admin/tool/oidc/callback/3", nil, nil, bearer)))
		require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/admin/user/1/release-managed", nil, nil, bearer)))
	}
	require.NotZero(t, responseCode(t, openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]any{"provider": 3, "linking": true}, nil, limited.AccessToken)))
	require.True(t, d.db.User.GetX(context.Background(), u.ID).SSOManaged)
	require.Zero(t, d.db.OpenIDTransaction.Query().CountX(context.Background()))
	w := openIDRequest(t, r, "GET", endpoint, nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	var discovery struct{ Data string }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &discovery))
	require.True(t, json.Valid([]byte(discovery.Data)))
	require.Zero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/admin/user/1/release-managed", nil, nil, token.AccessToken)))
	require.False(t, d.db.User.GetX(context.Background(), u.ID).SSOManaged)
}

func TestOpenIDCallbackProjectionMatchesEffectiveAuthorization(t *testing.T) {
	_, d, _, _, token := nativeFixture(t)
	permissions := &boolset.BooleanSet{}
	boolset.Set(types.GroupPermissionIsAdmin, true, permissions)
	require.NoError(t, d.db.Group.UpdateOneID(1).SetPermissions(permissions).Exec(context.Background()))
	t.Setenv(setting.EnvSettingOverwritePrefix+"siteURL", "https://canonical.example/cloudreve,https://alternate.example:8443/tenant/")
	d.s = setting.NewProvider(setting.NewEnvOverrideStore(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)), &authenticationLog{}))
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(ctx context.Context) string { return d.s.SiteURL(ctx).String() }})
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), dependency.DepCtx{}, d)
		ctx = context.WithValue(ctx, requestinfo.RequestInfoCtx{}, &requestinfo.RequestInfo{Host: c.Request.Host})
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}, middleware.CurrentUser())
	r.PUT("/api/v4/session/openid", middleware.RequiredScopes(types.ScopeUserSecurityInfoWrite), ctl.BeginOpenID)
	r.GET("/api/v4/admin/tool/oidc/callback/:provider_id", middleware.LoginRequired(), middleware.IsAdmin(), middleware.RequiredScopes(types.ScopeAdminWrite), ctl.OpenIDCallbackURI)
	for _, tc := range []struct{ origin, callback string }{
		{"http://admin.example", "https://canonical.example/cloudreve/callback/openid/3"},
		{"https://alternate.example:8443", "https://alternate.example:8443/tenant/callback/openid/3"},
	} {
		w := openIDRequest(t, r, "GET", tc.origin+"/api/v4/admin/tool/oidc/callback/3", nil, nil, token.AccessToken)
		require.Zero(t, responseCode(t, w))
		var projection struct{ Data string }
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &projection))
		require.Equal(t, tc.callback, projection.Data)
		w = openIDRequest(t, r, "PUT", tc.origin+"/api/v4/session/openid", map[string]int{"provider": 3}, nil)
		require.Zero(t, responseCode(t, w))
		var authorization struct{ Data string }
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &authorization))
		target, err := url.Parse(authorization.Data)
		require.NoError(t, err)
		require.Equal(t, projection.Data, target.Query().Get("redirect_uri"))
	}
	// Unsaved provider IDs also have a deterministic callback, without starting authentication.
	w := openIDRequest(t, r, "GET", "/api/v4/admin/tool/oidc/callback/99", nil, nil, token.AccessToken)
	require.Zero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "/callback/openid/99")
	for _, id := range []string{"-1", "invalid"} {
		require.NotZero(t, responseCode(t, openIDRequest(t, r, "GET", "/api/v4/admin/tool/oidc/callback/"+id, nil, nil, token.AccessToken)))
	}
}

func TestOpenIDDiscoveryRejectsUntrustedRedirectAndOversizedResponse(t *testing.T) {
	_, d, _, _, _ := nativeFixture(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted redirect was followed") }))
	defer other.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, other.URL, http.StatusFound)
		} else {
			w.Write([]byte(strings.Repeat("x", (2<<20)+1)))
		}
	}))
	defer source.Close()
	for _, path := range []string{"/redirect", "/large"} {
		_, err := d.o.Discovery(context.Background(), source.URL+path)
		require.Error(t, err)
	}
}
