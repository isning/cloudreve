package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	"github.com/cloudreve/Cloudreve/v4/service/basic"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// A log output sink records observable output; it does not replace persistence,
// authentication, settings or provider exchange behavior.
type authenticationLog struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func TestOpenIDBootstrapDefaultsAreRedacted(t *testing.T) {
	sink := &authenticationLog{}
	directory := t.TempDir()
	file := filepath.Join(directory, "conf.ini")
	content := "[System]\nDebug = true\n[Database]\nType = sqlite3\nDBFile = " + filepath.Join(directory, "startup.db") + "\n"
	require.NoError(t, os.WriteFile(file, []byte(content), 0600))
	config, err := conf.NewIniConfigProvider(file, sink)
	require.NoError(t, err)
	client, err := inventory.NewRawEntClient(sink, config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	raw := `{"version":1,"next_id":4,"providers":[{"id":3,"type":"oidc","enabled":false,"config":{"client_secret":"bootstrap-provider-secret"}}]}`
	t.Setenv(inventory.EnvDefaultOverwritePrefix+oidc.SettingName, raw)
	t.Setenv(inventory.EnvDefaultOverwritePrefix+"secret_key", "bootstrap-encryption-secret")
	_, err = inventory.InitializeDBClient(sink, client, cache.NewMemoStore("", sink), "4.14.0")
	require.NoError(t, err)
	require.NoError(t, inventory.EnsureExternalAuthSchema(context.Background(), client))
	output := sink.String()
	require.Contains(t, output, "[redacted]")
	require.NotContains(t, output, "bootstrap-provider-secret")
	require.NotContains(t, output, "bootstrap-encryption-secret")
}

func TestOpenIDEffectiveEncryptionKeyOverrideIsRedacted(t *testing.T) {
	sink := &authenticationLog{}
	t.Setenv(setting.EnvSettingOverwritePrefix+"secret_key", "runtime-encryption-secret")
	store := setting.NewEnvOverrideStore(nil, sink)
	require.Equal(t, "runtime-encryption-secret", store.Get(context.Background(), "secret_key", ""))
	require.Contains(t, sink.String(), "[redacted]")
	require.NotContains(t, sink.String(), "runtime-encryption-secret")
}

func (l *authenticationLog) write(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.data, format, args...)
	l.data.WriteByte('\n')
}
func (l *authenticationLog) Panic(f string, v ...any)             { panic(fmt.Sprintf(f, v...)) }
func (l *authenticationLog) Error(f string, v ...any)             { l.write(f, v...) }
func (l *authenticationLog) Warning(f string, v ...any)           { l.write(f, v...) }
func (l *authenticationLog) Info(f string, v ...any)              { l.write(f, v...) }
func (l *authenticationLog) Debug(f string, v ...any)             { l.write(f, v...) }
func (l *authenticationLog) CopyWithPrefix(string) logging.Logger { return l }
func (l *authenticationLog) SupportColor() bool                   { return false }
func (l *authenticationLog) String() string                       { l.mu.Lock(); defer l.mu.Unlock(); return l.data.String() }

func TestOpenIDCredentialsStayOutOfDebugLogs(t *testing.T) {
	_, d, p, _, local := nativeFixture(t)
	sink := &authenticationLog{}
	value, ok := authenticationDatabases.Load(d.db)
	require.True(t, ok)
	database := value.(authenticationDatabase)
	driver, err := entsql.Open(database.Driver, database.DSN)
	require.NoError(t, err)
	client := ent.NewClient(ent.Driver(debug.DebugWithContext(driver, func(ctx context.Context, args ...any) { sink.write("%v", args) })))
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	d.db = client
	d.s = setting.NewProvider(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)))
	d.native = auth.NewTokenAuth(d.encoder, d.s, []byte("fixture native signing key"), d.UserClient(), sink, d.kv, nil)
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(client), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), d.encoder, d.kv, d.s)})
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), dependency.DepCtx{}, d)
		ctx = context.WithValue(ctx, logging.LoggerCtx{}, sink)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}, middleware.Logging(), middleware.CurrentUser())
	r.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	r.POST("/api/v4/session/openid", ctl.FinishOpenID)
	r.PATCH("/api/v4/admin/settings", ctl.FromJSON[admin.SetSettingService](admin.SetSettingParamCtx{}), ctl.AdminSetSettings)
	r.GET("/api/v4/site/config/:section", ctl.FromUri[basic.GetSettingService](basic.GetSettingParamCtx{}), ctl.SiteConfig)
	r.DELETE("/api/v4/session/token", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserSignOut)
	r.GET("/callback/openid/:provider_id", func(c *gin.Context) { c.Status(200) })
	registry, err := d.s.ExternalLoginProviders(context.Background())
	require.NoError(t, err)
	registry.Providers[0].Wellknown.EndSessionEndpoint = p.server.URL + "/logout"
	raw, err := json.Marshal(registry)
	require.NoError(t, err)
	t.Setenv(setting.EnvSettingOverwritePrefix+oidc.SettingName, string(raw))
	_ = setting.NewEnvOverrideStore(nil, sink)
	// Ordinary SQL and transactional SQL both run with verbose debug enabled.
	w := openIDRequest(t, r, "PATCH", "/api/v4/admin/settings", map[string]any{"settings": map[string]string{oidc.SettingName: string(raw)}}, nil, local.AccessToken)
	require.Zero(t, responseCode(t, w), w.Body.String())
	target, proof := prepareExternal(t, r, 3, true, local.AccessToken)
	u, _ := url.Parse(target)
	code := p.code(t, target)
	w = openIDRequest(t, r, "GET", "/callback/openid/3?code="+url.QueryEscape(code)+"&state="+u.Query().Get("state"), nil, nil)
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	require.Zero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/openid", map[string]any{"provider_id": 3, "session_id": u.Query().Get("state"), "code": code}, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w = finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w))
	var login struct{ Data struct{ Token auth.Token } }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	require.Zero(t, responseCode(t, openIDRequest(t, r, "DELETE", "/api/v4/session/token", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)))
	w = openIDRequest(t, r, "GET", "/api/v4/site/config/login", nil, nil)
	require.Zero(t, responseCode(t, w))
	require.NotContains(t, w.Body.String(), "fixture-secret")
	output := sink.String()
	require.Contains(t, output, "[redacted]")
	require.Contains(t, output, "driver.Query")
	require.Contains(t, output, "Tx(")
	for _, secret := range []string{"fixture-secret", code, u.Query().Get("state"), u.Query().Get("nonce"), login.Data.Token.RefreshToken, login.Data.Token.AccessToken} {
		require.NotEmpty(t, secret)
		require.NotContains(t, output, secret)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, exchange := range p.exchanges {
		require.NotContains(t, output, exchange.Get("code_verifier"))
	}
	for _, token := range p.idTokens {
		require.NotContains(t, output, token)
	}
}
