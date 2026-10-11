package controllers_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/oauth"
	"github.com/stretchr/testify/require"
)

func TestOpenIDLoginCanContinueOrdinaryApplicationOAuth(t *testing.T) {
	r, d, p, _, local := nativeFixture(t)
	d.native = auth.NewTokenAuth(d.encoder, d.s, []byte("fixture native signing key"), d.UserClient(), logging.NewConsoleLogger(logging.LevelError), d.kv, d.OAuthClientClient())
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), d.encoder, d.kv, d.s)})
	_, err := d.db.OAuthClient.Create().SetGUID("desktop-fixture").SetSecret("desktop-fixture-secret").SetName("Desktop fixture").SetRedirectUris([]string{"http://127.0.0.1:49152/callback"}).SetScopes([]string{types.ScopeOpenID, types.ScopeOfflineAccess}).Save(context.Background())
	require.NoError(t, err)
	r.POST("/api/v4/session/oauth/consent", ctl.FromJSON[oauth.GrantService](oauth.GrantParamCtx{}), ctl.GrantAppConsent)
	r.POST("/api/v4/session/oauth/token", ctl.FromForm[oauth.ExchangeTokenService](oauth.ExchangeTokenParamCtx{}), ctl.ExchangeToken)
	target, proof := prepareExternal(t, r, 3, true, local.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w))
	var login struct{ Data struct{ Token auth.Token } }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	w = openIDRequest(t, r, "POST", "/api/v4/session/oauth/consent", map[string]string{"client_id": "desktop-fixture", "response_type": "code", "redirect_uri": "http://127.0.0.1:49152/callback", "scope": types.ScopeOpenID + " " + types.ScopeOfflineAccess, "state": "outer-application-state", "code_challenge": challenge, "code_challenge_method": "S256"}, nil, login.Data.Token.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	var consent struct{ Data oauth.GrantResponse }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &consent))
	require.Equal(t, "outer-application-state", consent.Data.State)
	require.NotEmpty(t, consent.Data.Code)
	form := url.Values{"client_id": {"desktop-fixture"}, "client_secret": {"desktop-fixture-secret"}, "grant_type": {"authorization_code"}, "code": {consent.Data.Code}, "redirect_uri": {"http://127.0.0.1:49152/callback"}, "code_verifier": {verifier}}
	req := httptest.NewRequest("POST", "/api/v4/session/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 200, w.Code, w.Body.String())
	var application oauth.TokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &application))
	require.NotEmpty(t, application.RefreshToken)
	appClaims, err := d.native.Claims(context.Background(), application.RefreshToken)
	require.NoError(t, err)
	require.Empty(t, appClaims.SessionSource)
	require.Equal(t, "desktop-fixture", appClaims.ClientID)
	externalClaims, err := d.native.Claims(context.Background(), login.Data.Token.RefreshToken)
	require.NoError(t, err)
	require.NotEqual(t, externalClaims.RootTokenID, appClaims.RootTokenID)
	require.Zero(t, responseCode(t, openIDRequest(t, r, "DELETE", "/api/v4/session/token", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)))
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": application.RefreshToken}, nil)
	require.Zero(t, responseCode(t, w), w.Body.String())
	// Existing application/grant validation still controls ordinary application refresh.
	_, err = d.db.OAuthGrant.Delete().Exec(context.Background())
	require.NoError(t, err)
	require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": application.RefreshToken}, nil)))
}
