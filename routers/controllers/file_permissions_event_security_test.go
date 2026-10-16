package controllers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/request"
	"github.com/cloudreve/Cloudreve/v4/routers"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsStreamRevalidatesUserOwnerAndGroup(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/live-status/seed.txt", []byte("seed"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/live-status", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	for _, change := range []string{"viewer", "owner", "group"} {
		f.loginAs(t, visitor.Email, password)
		stream := f.openPermissionStream(t, uri, "")
		stream.next(t, "subscribed")
		group := f.db.Group.GetX(context.Background(), 2)
		if change == "group" {
			denied := append(boolset.BooleanSet{}, (*group.Permissions)...)
			boolset.Set(types.GroupPermissionShareDownload, false, &denied)
			require.NoError(t, f.db.Group.UpdateOneID(2).SetPermissions(&denied).Exec(context.Background()))
		} else {
			id := 2
			if change == "viewer" {
				id = visitor.ID
			}
			require.NoError(t, f.db.User.UpdateOneID(id).SetStatus(user.StatusInactive).Exec(context.Background()))
		}
		stream.ticks <- time.Now()
		select {
		case <-stream.ended:
		case <-time.After(6 * time.Second):
			t.Fatal("idle stream survived current account/group denial")
		}
		stream.close()
		require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(user.StatusActive).Exec(context.Background()))
		require.NoError(t, f.db.User.UpdateOneID(visitor.ID).SetStatus(user.StatusActive).Exec(context.Background()))
		require.NoError(t, f.db.Group.UpdateOneID(2).SetPermissions(group.Permissions).Exec(context.Background()))
	}
}

func TestFilePermissionsStreamLosingAdminRoleFiltersDescendants(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	base := "cloudreve://my/admin-events"
	f.upload(t, base+"/hidden/seed.txt", []byte("private bytes"), nil)
	_, uri := f.createWritableShare(t, base, map[string]any{"everyone": "IQ=="})
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
		"uris": []string{base + "/hidden"}, "setting": map[string]string{"everyone": "AA=="},
	}, nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	stream := f.openPermissionStream(t, uri, "")
	stream.next(t, "subscribed")
	f.login(t)
	f.upload(t, base+"/hidden/before.txt", []byte("visible to an administrator"), nil)
	permissionStreamPath(t, stream, "/hidden/before.txt")
	// Drain identifying events legally delivered before the role change. A
	// later public arrival is an ordering barrier without a timing sleep.
	f.upload(t, base+"/barrier.txt", []byte("delivery barrier"), nil)
	permissionStreamPath(t, stream, "/barrier.txt")

	admin := f.db.User.Query().Where(user.Email("storage-admin@example.com")).WithGroup().OnlyX(context.Background())
	permissions := append(boolset.BooleanSet{}, (*admin.Edges.Group.Permissions)...)
	boolset.Set(types.GroupPermissionIsAdmin, false, &permissions)
	boolset.Set(types.GroupPermissionShareDownload, true, &permissions)
	require.NoError(t, f.db.Group.UpdateOneID(admin.GroupUsers).SetPermissions(&permissions).Exec(context.Background()))
	f.upload(t, base+"/hidden/after.txt", []byte("hidden after demotion"), nil)
	f.upload(t, base+"/public.txt", []byte("still allowed"), nil)
	found := false
	for i := 0; i < 20 && !found; i++ {
		message := assertPermissionStreamUntil(t, stream, "event", "/hidden/")
		found = strings.Contains(message.Data, "/public.txt")
	}
	require.True(t, found, "demotion must preserve permitted directory events")
	stream.ticks <- time.Now()
	message := assertPermissionStreamUntil(t, stream, "refresh", "/hidden/")
	require.Equal(t, "{}", message.Data)
}

func TestFilePermissionsStreamContextLimitDoesNotDisplaceActiveClients(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/context-limit/seed.txt", []byte("seed"), nil)
	streams := make([]*permissionSSE, 0, 64)
	for i := 0; i < 64; i++ {
		stream := f.openPermissionStream(t, "cloudreve://my/context-limit", "")
		stream.next(t, "subscribed")
		streams = append(streams, stream)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v4/file/events?uri="+url.QueryEscape("cloudreve://my/context-limit"), nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set(request.ClientIDHeader, uuid.Must(uuid.NewV4()).String())
	f.router.ServeHTTP(w, req)
	require.NotZero(t, permissionResponseCode(t, w.Body.Bytes()))
	streams[0].ticks <- time.Now()
	streams[0].next(t, "keep-alive")
	streams[1].close()
	next := f.openPermissionStream(t, "cloudreve://my/context-limit", "")
	next.next(t, "subscribed")
}

type permissionLogSink struct {
	sync.Mutex
	lines []string
}
type permissionCapturedLogger struct {
	logging.Logger
	sink   *permissionLogSink
	prefix string
}

func (l *permissionCapturedLogger) write(format string, args ...any) {
	l.sink.Lock()
	defer l.sink.Unlock()
	l.sink.lines = append(l.sink.lines, l.prefix+fmt.Sprintf(format, args...))
}
func (l *permissionCapturedLogger) Debug(f string, a ...any)   { l.write(f, a...) }
func (l *permissionCapturedLogger) Info(f string, a ...any)    { l.write(f, a...) }
func (l *permissionCapturedLogger) Warning(f string, a ...any) { l.write(f, a...) }
func (l *permissionCapturedLogger) Error(f string, a ...any)   { l.write(f, a...) }
func (l *permissionCapturedLogger) CopyWithPrefix(p string) logging.Logger {
	return &permissionCapturedLogger{Logger: l.Logger, sink: l.sink, prefix: l.prefix + p}
}

func TestFilePermissionsRecipientEventLogsContainNoHiddenPayload(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/log-security/hidden/seed.txt", []byte("private"), nil)
	id, _ := f.createWritableShare(t, "cloudreve://my/log-security", map[string]any{"everyone": "IQ=="})
	gate := storageRandom(t)[:8]
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/log-security", "is_private": true, "password": gate}, nil)
	uri := fs.NewShareUri(id, gate)
	visitor, password := f.createWritableVisitor(t, 2)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/log-security/hidden"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	sink := &permissionLogSink{}
	logger := &permissionCapturedLogger{Logger: logging.NewConsoleLogger(logging.LevelError), sink: sink}
	config, err := conf.NewIniConfigProvider(filepath.Join(t.TempDir(), "debug.ini"), logger)
	require.NoError(t, err)
	*config.Database() = f.database
	config.System().Debug = true
	// Use the native driver stack, including immutable SQL cancellation, with
	// verbose logging enabled. Raw driver wrappers bypass that production seam.
	debugDB, err := inventory.NewRawEntClient(logger, config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, debugDB.Close()) })
	d := dependency.NewDependency(dependency.WithDbClient(debugDB), dependency.WithConfigProvider(f.dep.ConfigProvider()), dependency.WithLogger(logger), dependency.WithKV(f.dep.KV()), dependency.WithHashIDEncoder(f.dep.HashIDEncoder()), dependency.WithSettingProvider(f.dep.SettingProvider()))
	t.Cleanup(func() { d.Shutdown(context.Background()) })
	f.dep = d
	f.router = routers.InitRouter(d)
	f.loginAs(t, visitor.Email, password)
	token := f.token
	stream := f.openPermissionStream(t, uri, "")
	stream.next(t, "subscribed")
	f.login(t)
	f.upload(t, "cloudreve://my/log-security/hidden/unexposed-name.txt", []byte("hidden event"), nil)
	f.upload(t, "cloudreve://my/log-security/visible.txt", []byte("visible"), nil)
	stream.next(t, "event")
	stream.ticks <- time.Now()
	stream.next(t, "keep-alive")
	stream.close()
	sink.Lock()
	var lines []string
	loggedSQL := false
	for _, line := range sink.lines {
		loggedSQL = loggedSQL || strings.Contains(line, "driver.Query:")
		if strings.Contains(line, stream.correlation) {
			lines = append(lines, line)
		}
	}
	sink.Unlock()
	require.True(t, loggedSQL, "native SQL debug logging must be enabled")
	text := strings.Join(lines, "\n")
	require.Contains(t, text, "filtered by current authorization")
	require.Contains(t, text, "File event delivered")
	for _, private := range []string{"unexposed-name.txt", "/hidden/", token, password, gate} {
		require.NotContains(t, text, private)
	}
}
