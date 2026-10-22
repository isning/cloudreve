package controllers_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/stretchr/testify/require"
)

// An opt-in production UI/router with disposable Ent and real object storage.
func TestOpenUserFilesBrowserRuntime(t *testing.T) {
	dir := os.Getenv("CLOUDREVE_OPEN_USER_FILES_BROWSER_DIR")
	if dir == "" {
		t.Skip("opt-in browser fixture")
	}
	f := newWritableShareFixture(t)
	for key, value := range map[string]string{"authn_enabled": "1", "avatar_path": "avatars", "avatar_size": "2097152", "avatar_size_l": "128", "gravatar_server": "https://www.gravatar.com/avatar/"} {
		f.db.Setting.Create().SetName(key).SetValue(value).OnConflictColumns(setting.FieldName).UpdateNewValues().ExecX(context.Background())
	}
	f.db.User.UpdateOneID(2).SetNick("Alex · Support workspace").ExecX(context.Background())
	f.upload(t, "cloudreve://my/support/child/readme.txt", []byte("Real target content for administrator browser acceptance."), nil)
	_, shareURI := f.createWritableShare(t, "cloudreve://my/support/child", map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/Shared guide", "type": "folder", "metadata": map[string]string{"sys:shared_redirect": shareURI}}, nil)
	visitor, password := f.createWritableVisitor(t, 2)
	f.db.User.UpdateOne(visitor).SetNick("Alex · Support workspace").ExecX(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: f.router, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { server.Close() })
	go server.Serve(listener)
	require.NoError(t, os.MkdirAll(dir, 0700))
	raw, err := json.Marshal(map[string]any{"url": "http://" + listener.Addr().String(), "admin_email": "storage-admin@example.com", "admin_password": f.adminPassword, "owner_email": "storage@example.com", "owner_password": f.password, "target_id": 2, "target_hash": hashid.EncodeUserID(f.dep.HashIDEncoder(), 2), "visitor_email": visitor.Email, "visitor_password": password, "visitor_id": visitor.ID, "visitor_hash": hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID)})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "credentials.json"), raw, 0600))
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt)
	defer signal.Stop(stopped)
	<-stopped
}
