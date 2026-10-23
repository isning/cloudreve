package controllers_test

import (
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	entsetting "github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/routers"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Opt-in native runtime for testing the independently built community frontend.
// Its credentials and all S3/database resources belong only to this fixture.
func TestFilePermissionsBrowserRuntime(t *testing.T) {
	dir := os.Getenv("CLOUDREVE_PERMISSION_BROWSER_DIR")
	if dir == "" {
		t.Skip("opt-in interactive browser fixture")
	}
	f := newWritableShareFixture(t)
	// Match an installed server while preserving fixture-specific persisted values.
	for name, value := range inventory.DefaultSettings {
		exists, err := f.db.Setting.Query().Where(entsetting.NameEQ(name)).Exist(context.Background())
		require.NoError(t, err)
		if !exists {
			require.NoError(t, f.db.Setting.Create().SetName(name).SetValue(value).Exec(context.Background()))
		}
	}
	f.immediatePermissionEvents(t)
	origin := os.Getenv("CLOUDREVE_PERMISSION_BROWSER_ORIGIN")
	if origin == "" {
		origin = "http://127.0.0.1:5212"
	}
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"siteURL": origin}}, nil)
	f.login(t)
	for _, policy := range f.policies {
		_, err := f.s3.PutBucketCors(&s3.PutBucketCorsInput{Bucket: aws.String(policy.BucketName), CORSConfiguration: &s3.CORSConfiguration{CORSRules: []*s3.CORSRule{{AllowedOrigins: aws.StringSlice([]string{origin}), AllowedMethods: aws.StringSlice([]string{"GET", "PUT", "POST", "DELETE", "HEAD"}), AllowedHeaders: aws.StringSlice([]string{"*"}), ExposeHeaders: aws.StringSlice([]string{"ETag"})}}}})
		require.NoError(t, err)
	}
	f.upload(t, "cloudreve://my/permission-ui/one.txt", []byte("permission browser bytes"), nil)
	f.upload(t, "cloudreve://my/permission-ui/nested/two.txt", []byte("second browser file"), nil)
	f.upload(t, "cloudreve://my/locked-ui/secret.txt", []byte("locked browser file"), nil)
	gate := storageRandom(t)[:8]
	var lockedLink string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/locked-ui", "is_private": true, "password": gate, "permissions": map[string]string{"everyone": "IQ=="}}, &lockedLink)
	_, singleURI := f.createWritableShare(t, "cloudreve://my/permission-ui/one.txt", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	_, shareURI := f.createWritableShare(t, "cloudreve://my/permission-ui", map[string]any{"everyone": "Lw==", "anonymous": "IQ=="})
	f.setPermissionDiscovery(t, true)
	if os.Getenv("CLOUDREVE_REVIEW_INVALID_DEFAULTS") == "1" {
		require.NoError(t, f.db.Setting.Update().Where(entsetting.NameEQ("default_symbolics")).SetValue("{invalid legacy configuration").Exec(context.Background()))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:5212")
	require.NoError(t, err)
	server := &http.Server{Handler: routers.InitRouter(f.dep), ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { server.Close() })
	go server.Serve(listener)
	require.NoError(t, os.MkdirAll(dir, 0700))
	raw, err := json.Marshal(map[string]any{"url": "http://127.0.0.1:5212", "frontend_url": origin, "owner_email": "storage@example.com", "owner_password": f.password, "admin_email": "storage-admin@example.com", "admin_password": f.adminPassword, "visitor_email": visitor.Email, "visitor_password": password, "share_uri": shareURI, "locked_link": lockedLink, "locked_password": gate, "single_uri": singleURI})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "credentials.json"), raw, 0600))
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt)
	defer signal.Stop(stopped)
	<-stopped
}
