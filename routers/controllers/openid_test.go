package controllers_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	"github.com/cloudreve/Cloudreve/v4/service/basic"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/ua-parser/uap-go/uaparser"
)

type openidTestDep struct {
	dependency.Dep
	db      *ent.Client
	kv      cache.Driver
	s       setting.Provider
	o       *oidc.Runtime
	native  auth.TokenAuth
	encoder hashid.Encoder
}

func (d *openidTestDep) FileClient() inventory.FileClient {
	return inventory.NewFileClient(d.db, conf.SQLiteDB, d.encoder)
}
func (d *openidTestDep) OAuthClientClient() inventory.OAuthClientClient {
	return inventory.NewOAuthClientClient(d.db, conf.SQLiteDB)
}
func (d *openidTestDep) UAParser() *uaparser.Parser       { return uaparser.NewFromSaved() }
func (d *openidTestDep) UserClient() inventory.UserClient { return inventory.NewUserClient(d.db) }
func (d *openidTestDep) TokenAuth() auth.TokenAuth        { return d.native }
func (d *openidTestDep) HashIDEncoder() hashid.Encoder    { return d.encoder }
func (d *openidTestDep) OIDC() *oidc.Runtime              { return d.o }

func (d *openidTestDep) WebAuthn(ctx context.Context) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{RPDisplayName: "Cloudreve fixture", RPID: "cloudreve.example", RPOrigins: []string{"https://cloudreve.example"}})
}

func TestOpenIDPrepareUsesPersistentBrowserTransaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c := openAuthenticationDatabase(t, "prepare.db")
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	require.NoError(t, inventory.EnsureExternalAuthSchema(context.Background(), c))
	d := &openidTestDep{db: c, kv: cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError))}
	d.s = setting.NewProvider(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)))
	raw := `{"version":1,"next_id":4,"providers":[{"id":3,"type":"oidc","enabled":true,"config":{"client_id":"cloudreve","client_secret":"fixture-secret"},"wellknown":{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","jwks_uri":"https://idp.example/jwks","code_challenge_methods_supported":["S256"]}}]}`
	_, err := c.Setting.Create().SetName("siteURL").SetValue("https://cloudreve.example").Save(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{"external_login_providers": raw}))
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(c), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }})
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	})
	r.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v4/session/openid", bytes.NewBufferString(`{"provider":3}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	var result struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	u, err := url.Parse(result.Data)
	require.NoError(t, err)
	require.Equal(t, "https://cloudreve.example/callback/openid/3", u.Query().Get("redirect_uri"))
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	require.NotEmpty(t, u.Query().Get("nonce"))
	require.NotEmpty(t, u.Query().Get("state"))
	require.Equal(t, "openid email profile", u.Query().Get("scope"))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].HttpOnly)
	require.True(t, cookies[0].Secure)
}

func (d *openidTestDep) DBClient() *ent.Client { return d.db }
func (d *openidTestDep) KV() cache.Driver      { return d.kv }
func (d *openidTestDep) SettingClient() inventory.SettingClient {
	return inventory.NewSettingClient(d.db, d.kv)
}
func (d *openidTestDep) SettingProvider() setting.Provider { return d.s }

func TestOpenIDProviderPublicConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c := openAuthenticationDatabase(t, "openid.db")
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	require.NoError(t, inventory.EnsureExternalAuthSchema(context.Background(), c))
	d := &openidTestDep{db: c, kv: cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError))}
	d.s = setting.NewProvider(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)))
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	})
	r.PATCH("/api/v4/admin/settings", ctl.FromJSON[admin.SetSettingService](admin.SetSettingParamCtx{}), ctl.AdminSetSettings)
	r.GET("/api/v4/site/config/:section", ctl.FromUri[basic.GetSettingService](basic.GetSettingParamCtx{}), ctl.SiteConfig)
	config := `{"version":1,"next_id":4,"providers":[{"id":3,"type":"oidc","enabled":true,"config":{"client_id":"cloudreve","client_secret":"fixture-secret","display_name":"Example login"},"wellknown":{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","jwks_uri":"https://idp.example/jwks"}}]}`
	body, err := json.Marshal(map[string]any{"settings": map[string]string{"external_login_providers": config}})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/v4/admin/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	var result struct {
		Code int
		Data json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v4/site/config/login", nil))
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code)
	require.Contains(t, string(result.Data), `"login_providers"`)
	require.Contains(t, string(result.Data), `"name":"Example login"`)
	require.NotContains(t, w.Body.String(), "fixture-secret")
}

// The fixture replaces only the external provider network. Cloudreve uses real
// Ent transactions, HTTP controllers and (in the login cases) native tokens.
type testIDP struct {
	server            *httptest.Server
	key               *rsa.PrivateKey
	mu                sync.Mutex
	codes             map[string]url.Values
	exchanges         []url.Values
	idTokens          []string
	subject           string
	email             string
	nonceOverride     string
	issuerOverride    string
	audienceOverride  any
	subjectOverride   string
	userinfoOverride  string
	userinfoMissing   bool
	expireOverride    bool
	signatureOverride bool
	claimsExtra       map[string]any
	logto             bool
}

func newTestIDP(t *testing.T) *testIDP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &testIDP{key: key, codes: map[string]url.Values{}, subject: "external-alice", email: "alice@example.com"}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oidc/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(oidc.Metadata{Issuer: p.server.URL + "/oidc", AuthorizationEndpoint: p.server.URL + "/authorize", TokenEndpoint: p.server.URL + "/token", UserinfoEndpoint: p.server.URL + "/userinfo", JWKSURI: p.server.URL + "/jwks", PKCEMethods: []string{"S256"}})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "fixture", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		case "/token":
			r.ParseForm()
			p.mu.Lock()
			p.exchanges = append(p.exchanges, r.Form)
			v, ok := p.codes[r.Form.Get("code")]
			delete(p.codes, r.Form.Get("code"))
			p.mu.Unlock()
			if !ok || r.Form.Get("client_secret") != "fixture-secret" || r.Form.Get("client_id") != "cloudreve" || r.Form.Get("redirect_uri") != v.Get("redirect_uri") {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			if v.Get("code_challenge") != "" {
				sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != v.Get("code_challenge") {
					w.WriteHeader(400)
					return
				}
			}
			nonce := v.Get("nonce")
			if p.nonceOverride != "" {
				nonce = p.nonceOverride
			}
			issuer := p.server.URL
			if p.logto {
				issuer += "/oidc"
			}
			if p.issuerOverride != "" {
				issuer = p.issuerOverride
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": issuer, "aud": "cloudreve", "sub": p.subject, "email": p.email, "name": "Alice", "nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
			claims := token.Claims.(jwt.MapClaims)
			if p.audienceOverride != nil {
				claims["aud"] = p.audienceOverride
			}
			if p.subjectOverride != "" {
				claims["sub"] = p.subjectOverride
			}
			if p.expireOverride {
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			}
			for key, value := range p.claimsExtra {
				claims[key] = value
			}
			token.Header["kid"] = "fixture"
			signingKey := p.key
			if p.signatureOverride {
				signingKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			signed, err := token.SignedString(signingKey)
			if err != nil {
				panic(err)
			}
			p.mu.Lock()
			p.idTokens = append(p.idTokens, signed)
			p.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"id_token": signed, "access_token": "fixture-access", "token_type": "Bearer", "expires_in": 60})
		case "/userinfo":
			subject := p.subject
			if p.userinfoOverride != "" {
				subject = p.userinfoOverride
			}
			info := map[string]any{"sub": subject, "email": p.email, "name": "Alice"}
			if p.userinfoMissing {
				delete(info, "sub")
			}
			for key, value := range p.claimsExtra {
				if key != "sub" {
					info[key] = value
				}
			}
			json.NewEncoder(w).Encode(info)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}
func (p *testIDP) code(t *testing.T, authorization string) string {
	u, err := url.Parse(authorization)
	require.NoError(t, err)
	p.mu.Lock()
	defer p.mu.Unlock()
	code := fmt.Sprintf("fixture-code-%d", len(p.codes)+time.Now().Nanosecond())
	p.codes[code] = u.Query()
	return code
}
func newOpenIDFixture(t *testing.T, p *testIDP) (*gin.Engine, *openidTestDep) {
	c := openAuthenticationDatabase(t, "flow.db")
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	require.NoError(t, inventory.EnsureExternalAuthSchema(context.Background(), c))
	d := &openidTestDep{db: c, kv: cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError))}
	d.s = setting.NewProvider(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)))
	_, err := c.Setting.Create().SetName("siteURL").SetValue("https://cloudreve.example").Save(context.Background())
	require.NoError(t, err)
	_, err = c.Setting.Create().SetName("siteID").SetValue("fixture-site-id").Save(context.Background())
	require.NoError(t, err)
	provider := oidc.Provider{ID: 3, Type: "oidc", Enabled: true, Config: oidc.Config{ClientID: "cloudreve", ClientSecret: "fixture-secret"}, Wellknown: oidc.Metadata{Issuer: p.server.URL, AuthorizationEndpoint: p.server.URL + "/authorize", TokenEndpoint: p.server.URL + "/token", UserinfoEndpoint: p.server.URL + "/userinfo", JWKSURI: p.server.URL + "/jwks", PKCEMethods: []string{"S256"}}}
	raw, err := json.Marshal(oidc.Registry{Version: 1, NextID: 4, Providers: []oidc.Provider{provider}})
	require.NoError(t, err)
	require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{"external_login_providers": string(raw)}))
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(c), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }})
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	})
	r.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	r.POST("/api/v4/session/openid", ctl.FinishOpenID)
	return r, d
}
func openIDRequest(t *testing.T, r *gin.Engine, method, path string, body any, cookie *http.Cookie, token ...string) *httptest.ResponseRecorder {
	data, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if len(token) > 0 && token[0] != "" {
		req.Header.Set("Authorization", "Bearer "+token[0])
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func TestOpenIDForeignBrowserDoesNotConsumeTransaction(t *testing.T) {
	p := newTestIDP(t)
	r, _ := newOpenIDFixture(t, p)
	w := openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]int{"provider": 3}, nil)
	var prepare struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &prepare))
	require.Zero(t, prepare.Code, w.Body.String())
	cookie := w.Result().Cookies()[0]
	u, err := url.Parse(prepare.Data)
	require.NoError(t, err)
	body := map[string]any{"provider_id": 3, "session_id": u.Query().Get("state"), "code": p.code(t, prepare.Data)}
	foreign := *cookie
	foreign.Value = "foreign-browser"
	w = openIDRequest(t, r, "POST", "/api/v4/session/openid", body, &foreign)
	require.Contains(t, w.Body.String(), "browser")
	w = openIDRequest(t, r, "POST", "/api/v4/session/openid", body, cookie)
	require.Contains(t, w.Body.String(), "associate")
	w = openIDRequest(t, r, "POST", "/api/v4/session/openid", body, cookie)
	require.Contains(t, w.Body.String(), "transaction")
}

func TestOpenIDExplicitBindingReturnsNoSession(t *testing.T) {
	p := newTestIDP(t)
	_, d := newOpenIDFixture(t, p)
	for i := 1; i <= 3; i++ {
		_, err := d.db.Group.Create().SetName(fmt.Sprintf("Group %d", i)).SetPermissions(&boolset.BooleanSet{}).Save(context.Background())
		require.NoError(t, err)
	}
	u, err := inventory.NewUserClient(d.db).Create(context.Background(), &inventory.NewUserArgs{Email: "local@example.com", PlainPassword: "local-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	// Authentication is real; this middleware only supplies the usual CurrentUser
	// stage omitted by the focused HTTP fixture's intentionally small router.
	encoder, err := hashid.New("fixture")
	require.NoError(t, err)
	native := auth.NewTokenAuth(encoder, d.s, []byte("fixture native signing key"), inventory.NewUserClient(d.db), logging.NewConsoleLogger(logging.LevelError), d.kv, nil)
	token, err := native.Issue(context.Background(), &auth.IssueTokenArgs{User: u})
	require.NoError(t, err)
	d.native = native
	d.encoder = encoder
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(native, inventory.NewUserClient(d.db), encoder, d.kv, d.s)})
	// Apply the standard native authentication stage for binding.
	flow := gin.New()
	flow.ContextWithFallback = true
	flow.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	}, middleware.CurrentUser())
	flow.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	flow.POST("/api/v4/session/openid", ctl.FinishOpenID)
	data := bytes.NewBufferString(`{"provider":3,"linking":true}`)
	req := httptest.NewRequest("PUT", "/api/v4/session/openid", data)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	w := httptest.NewRecorder()
	flow.ServeHTTP(w, req)
	var result struct {
		Code int
		Data json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	var authorization string
	require.NoError(t, json.Unmarshal(result.Data, &authorization))
	target, err := url.Parse(authorization)
	require.NoError(t, err)
	w = openIDRequest(t, flow, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "session_id": target.Query().Get("state"), "code": p.code(t, authorization)}, w.Result().Cookies()[0])
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	var binding struct {
		Code int
		Data json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &binding))
	require.Zero(t, binding.Code)
	require.True(t, len(binding.Data) == 0 || string(binding.Data) == "null", w.Body.String())
	// The subsequent provider login opens this account and signs native credentials.
	w = openIDRequest(t, flow, "PUT", "/api/v4/session/openid", map[string]int{"provider": 3}, nil)
	var prepared struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &prepared))
	require.Zero(t, prepared.Code)
	target, err = url.Parse(prepared.Data)
	require.NoError(t, err)
	w = openIDRequest(t, flow, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "session_id": target.Query().Get("state"), "code": p.code(t, prepared.Data)}, w.Result().Cookies()[0])
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	var login struct {
		User struct {
			ID    string
			Email string
		}
		Token auth.Token
	}
	require.NoError(t, json.Unmarshal(result.Data, &login))
	require.Equal(t, hashid.EncodeUserID(encoder, u.ID), login.User.ID)
	require.Equal(t, "local@example.com", login.User.Email)
	claims, err := native.Claims(context.Background(), login.Token.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "openid", claims.SessionSource)
	flow.POST("/api/v4/session/token/refresh", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserRefreshToken)
	flow.DELETE("/api/v4/session/token", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserSignOut)
	w = openIDRequest(t, flow, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": login.Token.RefreshToken}, nil)
	var refreshed struct {
		Code int
		Data auth.Token
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshed))
	require.Zero(t, refreshed.Code, w.Body.String())
	renewed, err := native.Claims(context.Background(), refreshed.Data.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, claims.RootTokenID, renewed.RootTokenID)
	require.Equal(t, "openid", renewed.SessionSource)
	w = openIDRequest(t, flow, "DELETE", "/api/v4/session/token", map[string]string{"refresh_token": login.Token.RefreshToken}, nil)
	var logout struct{ Code int }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &logout))
	require.Zero(t, logout.Code, w.Body.String())
	// A fresh runtime with another default cache must observe persistent revocation.
	otherNative := auth.NewTokenAuth(encoder, d.s, []byte("fixture native signing key"), d.UserClient(), logging.NewConsoleLogger(logging.LevelError), cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)), nil)
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(otherNative, d.UserClient(), encoder, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)), d.s)})
	w = openIDRequest(t, flow, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": refreshed.Data.RefreshToken}, nil)
	var rejected struct{ Code int }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rejected))
	require.NotZero(t, rejected.Code, w.Body.String())

}

func TestManagedAccountCannotUseLocalPassword(t *testing.T) {
	p := newTestIDP(t)
	_, d := newOpenIDFixture(t, p)
	for i := 1; i <= 3; i++ {
		_, err := d.db.Group.Create().SetName(fmt.Sprintf("Group %d", i)).SetPermissions(&boolset.BooleanSet{}).Save(context.Background())
		require.NoError(t, err)
	}
	u, err := d.UserClient().Create(context.Background(), &inventory.NewUserArgs{Email: "managed@example.com", PlainPassword: "local-password", Status: entuser.StatusActive, GroupID: 2})
	require.NoError(t, err)
	_, err = d.db.User.UpdateOne(u).SetSSOManaged(true).Save(context.Background())
	require.NoError(t, err)
	flow := gin.New()
	flow.ContextWithFallback = true
	flow.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	})
	flow.POST("/api/v4/session/token", ctl.FromJSON[usersvc.UserLoginService](usersvc.LoginParameterCtx{}), ctl.UserLoginValidation, func(c *gin.Context) { c.JSON(200, map[string]int{"code": 0}) })
	w := openIDRequest(t, flow, "POST", "/api/v4/session/token", map[string]string{"email": "managed@example.com", "password": "local-password"}, nil)
	var result struct{ Code int }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.NotZero(t, result.Code, w.Body.String())
}

func TestOpenIDAutoCreationDoesNotBootstrapAdministrator(t *testing.T) {
	p := newTestIDP(t)
	r, d := newOpenIDFixture(t, p)
	for i := 1; i <= 3; i++ {
		_, err := d.db.Group.Create().SetName(fmt.Sprintf("Group %d", i)).SetPermissions(&boolset.BooleanSet{}).Save(context.Background())
		require.NoError(t, err)
	}
	encoder, err := hashid.New("fixture")
	require.NoError(t, err)
	d.encoder = encoder
	d.native = auth.NewTokenAuth(encoder, d.s, []byte("fixture native signing key"), d.UserClient(), logging.NewConsoleLogger(logging.LevelError), d.kv, nil)
	registry, err := d.s.ExternalLoginProviders(context.Background())
	require.NoError(t, err)
	registry.Providers[0].Config.DirectSignIn = true
	raw, err := json.Marshal(registry)
	require.NoError(t, err)
	require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{oidc.SettingName: string(raw)}))
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(d.db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, DefaultGroup: func(context.Context) int { return 2 }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), encoder, d.kv, d.s)})
	w := openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]int{"provider": 3}, nil)
	var prepare struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &prepare))
	require.Zero(t, prepare.Code)
	target, err := url.Parse(prepare.Data)
	require.NoError(t, err)
	w = openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "session_id": target.Query().Get("state"), "code": p.code(t, prepare.Data)}, w.Result().Cookies()[0])
	var result struct {
		Code int
		Data struct {
			User struct {
				ID    string
				Email string
				Group struct{ ID string }
			}
			Token auth.Token
		}
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	require.Equal(t, "alice@example.com", result.Data.User.Email)
	require.Equal(t, hashid.EncodeGroupID(encoder, 2), result.Data.User.Group.ID)
	secret := "JBSWY3DPEHPK3PXP"
	_, err = d.db.User.Update().SetTwoFactorSecret(secret).Save(context.Background())
	require.NoError(t, err)
	r.POST("/api/v4/session/token/2fa", ctl.FromJSON[usersvc.OtpValidationService](usersvc.OtpValidationParameterCtx{}), ctl.UserLogin2FAValidation, ctl.UserIssueToken)
	w = openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]int{"provider": 3}, nil)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &prepare))
	target, err = url.Parse(prepare.Data)
	require.NoError(t, err)
	w = openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "session_id": target.Query().Get("state"), "code": p.code(t, prepare.Data)}, w.Result().Cookies()[0])
	var challenge struct {
		Code int
		Data string
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.Equal(t, 203, challenge.Code, w.Body.String())
	proof := w.Result().Cookies()[0]
	otp, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/2fa", map[string]string{"otp": otp, "session_id": challenge.Data}, nil)
	var failure struct{ Code int }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &failure))
	require.NotZero(t, failure.Code)
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/2fa", map[string]string{"otp": "wrong", "session_id": challenge.Data}, proof)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &failure))
	require.NotZero(t, failure.Code)
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/2fa", map[string]string{"otp": otp, "session_id": challenge.Data}, proof)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	claims, err := d.native.Claims(context.Background(), result.Data.Token.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "openid", claims.SessionSource)
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/2fa", map[string]string{"otp": otp, "session_id": challenge.Data}, proof)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &failure))
	require.NotZero(t, failure.Code)

}

func TestLogtoPrepareAdaptsConnectorAndHint(t *testing.T) {
	for _, connector := range []string{"social:google", "sso:fixture-connector"} {
		t.Run(connector, func(t *testing.T) {
			p := newTestIDP(t)
			r, d := newOpenIDFixture(t, p)
			registry, err := d.s.ExternalLoginProviders(context.Background())
			require.NoError(t, err)
			registry.Providers[0] = oidc.Provider{ID: 3, Type: "logto", Enabled: true, Config: oidc.Config{Endpoint: p.server.URL, AppID: "cloudreve", AppSecret: "fixture-secret", DirectSSO: connector, DirectSignIn: true}}
			raw, err := json.Marshal(registry)
			require.NoError(t, err)
			require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{oidc.SettingName: string(raw)}))
			for _, hint := range []string{"", "alice@example.com"} {
				w := openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]any{"provider": 3, "hint": hint}, nil)
				var result struct {
					Code int
					Data string
				}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
				require.Zero(t, result.Code)
				target, err := url.Parse(result.Data)
				require.NoError(t, err)
				require.Equal(t, connector, target.Query().Get("direct_sign_in"))
				require.Equal(t, hint, target.Query().Get("login_hint"))
				require.Equal(t, "cloudreve", target.Query().Get("client_id"))
			}
		})
	}
}
