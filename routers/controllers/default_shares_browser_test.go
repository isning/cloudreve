package controllers_test

import (
	"context"
	"encoding/json"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDefaultSharesBrowserRuntime serves real production HTTP/UI for opt-in
// interactive acceptance; the fixture credentials never enter tracked files.
func TestDefaultSharesBrowserRuntime(t *testing.T) {
	dir := os.Getenv("CLOUDREVE_DEFAULT_SHARES_BROWSER_DIR")
	if dir == "" {
		t.Skip("opt-in browser fixture")
	}
	f := newWritableShareFixture(t)
	for key, value := range map[string]string{"register_enabled": "1", "email_active": "0", "authn_enabled": "1", "expose_user_email": "0", "default_group": "2", "avatar_path": "avatars", "avatar_size": "2097152", "avatar_size_l": "128", "gravatar_server": "https://www.gravatar.com/avatar/"} {
		require.NoError(t, f.db.Setting.Create().SetName(key).SetValue(value).OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(context.Background()))
	}

	first, _ := f.defaultShare(t, "Getting started")
	second, _ := f.defaultShare(t, "Team resources")
	// Leave the recommendation empty so the browser exercises configuration.
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t)
	listener, err := net.Listen("tcp", "127.0.0.1:5212")
	require.NoError(t, err)
	server := &http.Server{Handler: f.router, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { server.Close() })
	go server.Serve(listener)
	require.NoError(t, os.MkdirAll(dir, 0700))
	raw, err := json.Marshal(map[string]any{"url": "http://127.0.0.1:5212", "admin_email": "storage-admin@example.com", "admin_password": f.adminPassword, "owner_email": "storage@example.com", "owner_password": f.password, "visitor_email": visitor.Email, "visitor_password": password, "first": first, "second": second})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "credentials.json"), raw, 0600))
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt)
	defer signal.Stop(stopped)
	<-stopped
}
