package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/middleware"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// The subprocess shares only the database and configured cryptographic keys.
// Its Ent connection pool, runtime, JWT service and default cache are independent.
func TestOpenIDProcessWorker(t *testing.T) {
	file := os.Getenv("OIDC_PROCESS_CONFIG")
	if file == "" {
		t.Skip("subprocess worker")
	}
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var config authenticationDatabase
	require.NoError(t, json.Unmarshal(raw, &config))
	db, err := ent.Open(config.Driver, config.DSN)
	require.NoError(t, err)
	defer db.Close()
	l := logging.NewConsoleLogger(logging.LevelError)
	d := &openidTestDep{db: db, kv: cache.NewMemoStore("", l)}
	d.s = setting.NewProvider(setting.NewDbSettingStore(d.SettingClient(), setting.NewDbDefaultStore(nil)))
	d.encoder, err = hashid.New("fixture")
	require.NoError(t, err)
	d.native = auth.NewTokenAuth(d.encoder, d.s, []byte("fixture native signing key"), d.UserClient(), l, d.kv, nil)
	d.o = oidc.New(oidc.Options{Registry: d.s.ExternalLoginProviders, Store: inventory.NewExternalAuthStore(db), Key: []byte("fixture encryption key"), SiteURL: func(context.Context) string { return "https://cloudreve.example" }, Native: auth.NewOIDCSessionBridge(d.native, d.UserClient(), d.encoder, d.kv, d.s)})
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.ContextWithFallback = true
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), dependency.DepCtx{}, d))
		c.Next()
	}, middleware.CurrentUser())
	r.PUT("/api/v4/session/openid", ctl.BeginOpenID)
	r.POST("/api/v4/session/openid", ctl.FinishOpenID)
	r.POST("/api/v4/session/token/refresh", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserRefreshToken)
	r.DELETE("/api/v4/session/token", ctl.FromJSON[usersvc.RefreshTokenService](usersvc.RefreshTokenParameterCtx{}), ctl.UserSignOut)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt)
	defer signal.Stop(stopped)
	go server.Serve(listener)
	require.NoError(t, os.WriteFile(file+".ready", []byte("http://"+listener.Addr().String()), 0600))
	<-stopped
	require.NoError(t, server.Close())
}

func independentProcess(t *testing.T, d *openidTestDep) string {
	t.Helper()
	value, ok := authenticationDatabases.Load(d.db)
	require.True(t, ok)
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "process.json")
	require.NoError(t, os.WriteFile(file, raw, 0600))
	cmd := exec.Command(os.Args[0], "-test.run=^TestOpenIDProcessWorker$", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "OIDC_PROCESS_CONFIG="+file)
	log, err := os.Create(file + ".log")
	require.NoError(t, err)
	cmd.Stdout = log
	cmd.Stderr = log
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		require.NoError(t, cmd.Wait())
		require.NoError(t, log.Close())
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ready, err := os.ReadFile(file + ".ready")
		if err == nil {
			return string(ready)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("independent authentication process did not start")
	return ""
}

func processRequest(t *testing.T, server, method, path string, body any, proof *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, server+path, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if proof != nil {
		req.AddCookie(proof)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	w := httptest.NewRecorder()
	w.Code = res.StatusCode
	_, err = io.Copy(w.Body, res.Body)
	require.NoError(t, err)
	return w
}

func TestOpenIDCrossProcessProofConsumptionAndRevocation(t *testing.T) {
	r, d, p, _, native := nativeFixture(t)
	other := independentProcess(t, d)
	target, proof := prepareExternal(t, r, 3, true, native.AccessToken)
	u, err := url.Parse(target)
	require.NoError(t, err)
	body := map[string]any{"provider_id": 3, "session_id": u.Query().Get("state"), "code": p.code(t, target)}
	require.Zero(t, responseCode(t, processRequest(t, other, "POST", "/api/v4/session/openid", body, proof)))
	require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/openid", body, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	u, err = url.Parse(target)
	require.NoError(t, err)
	body = map[string]any{"provider_id": 3, "session_id": u.Query().Get("state"), "code": p.code(t, target)}
	w := processRequest(t, other, "POST", "/api/v4/session/openid", body, proof)
	require.Zero(t, responseCode(t, w), w.Body.String())
	var result struct{ Data struct{ Token oidc.Token } }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.NotEmpty(t, result.Data.Token.RefreshToken)
	claims, err := d.native.Claims(context.Background(), result.Data.Token.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, "openid", claims.SessionSource)
	refresh := map[string]string{"refresh_token": result.Data.Token.RefreshToken}
	w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", refresh, nil)
	require.Zero(t, responseCode(t, w), w.Body.String())
	require.Zero(t, responseCode(t, processRequest(t, other, "DELETE", "/api/v4/session/token", refresh, nil)))
	require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", refresh, nil)))
	// Hot configuration is authoritative across independent caches as well.
	target, proof = prepareExternal(t, r, 3, false, "")
	u, _ = url.Parse(target)
	changeProvider(t, d, func(registry *oidc.Registry) { registry.Providers[0].Enabled = false })
	body = map[string]any{"provider_id": 3, "session_id": u.Query().Get("state"), "code": p.code(t, target)}
	w = processRequest(t, other, "POST", "/api/v4/session/openid", body, proof)
	require.NotZero(t, responseCode(t, w))
	require.Contains(t, w.Body.String(), "provider")
}
