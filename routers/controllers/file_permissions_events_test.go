package controllers_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/fsevent"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/eventhub"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/request"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

type permissionSSEMessage struct{ Kind, Data string }
type permissionSSE struct {
	messages    chan permissionSSEMessage
	ended       chan struct{}
	ticks       chan time.Time
	close       func()
	correlation string
}

func (f *storageFixture) openPermissionStream(t *testing.T, uri, client string) *permissionSSE {
	t.Helper()
	if client == "" {
		client = uuid.Must(uuid.NewV4()).String()
	}
	ticks := make(chan time.Time, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), explorer.EventStreamTickerCtx{}, explorer.EventStreamTicker(func(d time.Duration) (<-chan time.Time, func()) {
			if d > 30*time.Second {
				panic("stream refresh interval exceeded")
			}
			return ticks, func() {}
		}))
		f.router.ServeHTTP(w, r.WithContext(ctx))
	}))
	ctx, cancel := context.WithCancel(context.Background())
	base := srv.URL
	if f.remote != "" {
		base = f.remote
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v4/file/events?uri="+url.QueryEscape(uri), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set(request.ClientIDHeader, client)
	correlation := uuid.Must(uuid.NewV4()).String()
	req.Header.Set(request.CorrelationHeader, correlation)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	if !strings.Contains(res.Header.Get("Content-Type"), "text/event-stream") {
		res.Body.Close()
		cancel()
		srv.Close()
		t.Fatal("native stream subscription was rejected")
	}
	s := &permissionSSE{messages: make(chan permissionSSEMessage, 256), ended: make(chan struct{}), ticks: ticks, correlation: correlation}
	s.close = func() { cancel(); res.Body.Close(); srv.Close() }
	t.Cleanup(s.close)
	go func() {
		defer close(s.ended)
		scan := bufio.NewScanner(res.Body)
		var message permissionSSEMessage
		for scan.Scan() {
			line := scan.Text()
			if line == "" {
				if message.Kind != "" {
					select {
					case s.messages <- message:
					case <-ctx.Done():
						return
					}
				}
				message = permissionSSEMessage{}
			} else if strings.HasPrefix(line, "event:") {
				message.Kind = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				message.Data += strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
		}
	}()
	return s
}
func (s *permissionSSE) next(t *testing.T, kind string) permissionSSEMessage {
	t.Helper()
	timeout := time.NewTimer(12 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case msg := <-s.messages:
			if msg.Kind == kind {
				return msg
			}
		case <-s.ended:
			t.Fatalf("stream ended before %s", kind)
			return permissionSSEMessage{}
		case <-timeout.C:
			t.Fatalf("stream timed out before %s", kind)
			return permissionSSEMessage{}
		}
	}
}
func (f *storageFixture) immediatePermissionEvents(t *testing.T) {
	t.Helper()
	require.NoError(t, f.db.Setting.Create().SetName("fs_event_push_debounce").SetValue("5").OnConflictColumns("name").UpdateName().Exec(context.Background()))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"fs_event_push_debounce": "0"}}, nil)
	f.login(t)
}
func TestFilePermissionsOwnerStreamingHTTP(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/events/seed.txt", []byte("seed"), nil)
	stream := f.openPermissionStream(t, "cloudreve://my/events", "")
	stream.next(t, "subscribed")
	f.upload(t, "cloudreve://my/events/created.txt", []byte("actual event content"), nil)
	message := stream.next(t, "event")
	var evt eventhub.Event
	require.NoError(t, json.Unmarshal([]byte(message.Data), &evt))
	require.Contains(t, []string{eventhub.EventTypeCreate, eventhub.EventTypeModify}, string(evt.Type))
	require.Equal(t, "/created.txt", evt.From)
	require.NotEmpty(t, evt.FileID)
	stream.ticks <- time.Now().Add(30 * time.Second)
	stream.next(t, "keep-alive")
}

func TestFilePermissionsPrivilegedShareStreamsPreserveNativeEvents(t *testing.T) {
	for _, role := range []string{"owner", "admin"} {
		t.Run(role, func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.immediatePermissionEvents(t)
			base := "cloudreve://my/privileged-events"
			f.upload(t, base+"/old.txt", []byte("owner bytes"), nil)
			_, uri := f.createWritableShare(t, base, map[string]any{"everyone": "IQ=="})
			personal := f.openPermissionStream(t, base, "")
			personal.next(t, "subscribed")
			if role == "admin" {
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			}
			shared := f.openPermissionStream(t, uri, "")
			shared.next(t, "subscribed")
			f.login(t)
			f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": base + "/old.txt", "new_name": "new.txt"}, nil)
			for _, stream := range []*permissionSSE{personal, shared} {
				event := permissionStreamPath(t, stream, "/new.txt")
				require.Equal(t, eventhub.EventTypeRename, string(event.Type))
				require.Equal(t, "/old.txt", event.From)
				require.Equal(t, "/new.txt", event.To)
			}
			f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{base + "/new.txt"}}, nil)
			for _, stream := range []*permissionSSE{personal, shared} {
				event := permissionStreamPath(t, stream, "/new.txt")
				require.Equal(t, eventhub.EventTypeDelete, string(event.Type))
			}
			shared.ticks <- time.Now()
			select {
			case message := <-shared.messages:
				require.Equal(t, "keep-alive", message.Kind, "periodic recipient refresh must not alter privileged streams")
			case <-time.After(5 * time.Second):
				t.Fatal("privileged stream did not send its heartbeat")
			}
		})
	}
}

func TestFilePermissionsSubscriptionContextIsolation(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/context/seed.txt", []byte("context"), nil)
	_, first := f.createWritableShare(t, "cloudreve://my/context", map[string]any{"everyone": "IQ=="})
	_, second := f.createWritableShare(t, "cloudreve://my/context", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	client := uuid.Must(uuid.NewV4()).String()
	owner := f.openPermissionStream(t, "cloudreve://my/context", client)
	owner.next(t, "subscribed")
	f.loginAs(t, visitor.Email, password)
	a := f.openPermissionStream(t, first, client)
	a.next(t, "subscribed")
	b := f.openPermissionStream(t, second, client)
	b.next(t, "subscribed")
	f.login(t)
	f.upload(t, "cloudreve://my/context/visible.txt", []byte("new context bytes"), nil)
	owner.next(t, "event")
	// Other contexts sharing the raw sync UUID do not take over the owner queue.
	a.close()
	f.upload(t, "cloudreve://my/context/another.txt", []byte("still subscribed"), nil)
	owner.next(t, "event")
	b.ticks <- time.Now()
	b.next(t, "keep-alive")
}

func assertPermissionStreamUntil(t *testing.T, s *permissionSSE, kind, hidden string) permissionSSEMessage {
	t.Helper()
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case msg := <-s.messages:
			if hidden != "" {
				require.NotContains(t, msg.Data, hidden, "stream exposed a hidden descendant")
			}
			if msg.Kind == kind {
				return msg
			}
		case <-s.ended:
			t.Fatal("stream ended before controlled checkpoint")
			return permissionSSEMessage{}
		case <-deadline.C:
			t.Fatal("stream did not reach controlled checkpoint")
			return permissionSSEMessage{}
		}
	}
}
func TestFilePermissionsSharedStreamsUseCurrentDescendantACL(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/stream/private/seed.txt", []byte("private seed"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/stream", map[string]any{"everyone": "IQ=="})
	a, passwordA := f.createWritableVisitor(t, 2)
	b, passwordB := f.createWritableVisitor(t, 2)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/stream/private"}, "setting": map[string]any{"everyone": "IQ==", "user_explicit": map[string]string{hashid.EncodeUserID(f.dep.HashIDEncoder(), a.ID): "AA=="}}}, nil)
	f.loginAs(t, a.Email, passwordA)
	first := f.openPermissionStream(t, uri, "")
	first.next(t, "subscribed")
	f.loginAs(t, b.Email, passwordB)
	second := f.openPermissionStream(t, uri, "")
	second.next(t, "subscribed")
	f.login(t)
	f.upload(t, "cloudreve://my/stream/private/secret.txt", []byte("hidden event bytes"), nil)
	visible := second.next(t, "event")
	require.Contains(t, visible.Data, "/private/secret.txt")
	first.ticks <- time.Now().Add(30 * time.Second)
	refresh := assertPermissionStreamUntil(t, first, "refresh", "secret.txt")
	require.NotContains(t, refresh.Data, "file_id")
	require.NotContains(t, refresh.Data, "private")
	f.upload(t, "cloudreve://my/stream/public.txt", []byte("public event bytes"), nil)
	public := first.next(t, "event")
	require.Contains(t, public.Data, "/public.txt")
	require.NotContains(t, public.Data, "secret.txt")
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/stream/private"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	f.upload(t, "cloudreve://my/stream/private/revoked.txt", []byte("revoked event"), nil)
	second.ticks <- time.Now().Add(30 * time.Second)
	assertPermissionStreamUntil(t, second, "refresh", "revoked.txt")
}

func permissionStreamPath(t *testing.T, s *permissionSSE, expected string) eventhub.Event {
	t.Helper()
	for i := 0; i < 20; i++ {
		message := s.next(t, "event")
		var evt eventhub.Event
		require.NoError(t, json.Unmarshal([]byte(message.Data), &evt))
		if evt.From == expected || evt.To == expected {
			return evt
		}
	}
	t.Fatal("stream did not expose the expected authorized path")
	return eventhub.Event{}
}
func TestFilePermissionsRenameNeverReplaysAnOldHiddenName(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/rename/old-name.txt", []byte("rename"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/rename", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	stream := f.openPermissionStream(t, uri, "")
	stream.next(t, "subscribed")
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": "cloudreve://my/rename/old-name.txt", "new_name": "current-name.txt"}, nil)
	event := permissionStreamPath(t, stream, "/current-name.txt")
	require.Equal(t, eventhub.EventTypeCreate, string(event.Type))
	require.Empty(t, event.To)
	require.NotContains(t, event.From, "old-name")
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/rename/current-name.txt"}}, nil)
	stream.ticks <- time.Now().Add(30 * time.Second)
	assertPermissionStreamUntil(t, stream, "refresh", "current-name.txt")
}
func TestFilePermissionsPeriodicRefreshRevalidatesShareRoot(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/revoke/file.txt", []byte("revoke"), nil)
	id, uri := f.createWritableShare(t, "cloudreve://my/revoke", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	stream := f.openPermissionStream(t, uri, "")
	stream.next(t, "subscribed")
	stream.ticks <- time.Now().Add(30 * time.Second)
	refresh := stream.next(t, "refresh")
	require.Equal(t, "{}", refresh.Data)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/revoke", "permissions": map[string]string{"everyone": "AA==", "anonymous": "AA=="}}, nil)
	stream.ticks <- time.Now().Add(60 * time.Second)
	select {
	case <-stream.ended:
	case <-time.After(10 * time.Second):
		t.Fatal("revoked root kept its idle stream")
	}
}

func TestFilePermissionsMovedFilesRevealOnlyCurrentlyVisibleArrival(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/move-events/from/secret-name.txt", []byte("move bytes"), nil)
	f.upload(t, "cloudreve://my/move-events/to/seed.txt", []byte("seed"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/move-events", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/move-events/from"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	stream := f.openPermissionStream(t, uri, "")
	stream.next(t, "subscribed")
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/move-events/from/secret-name.txt"}, "dst": "cloudreve://my/move-events/to"}, nil)
	msg := assertPermissionStreamUntil(t, stream, "event", "/from/")
	require.Contains(t, msg.Data, "/to/secret-name.txt")
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/move-events/to/secret-name.txt"}, "dst": "cloudreve://my/move-events/from"}, nil)
	stream.ticks <- time.Now()
	assertPermissionStreamUntil(t, stream, "refresh", "secret-name.txt")
}

func TestFilePermissionsOfflineReplaySurvivesRestartAndFiltersCurrentACL(t *testing.T) {
	t.Setenv("CLOUDREVE_PERMISSION_FULL_ROUTER", "1")
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/replay/seed.txt", []byte("seed"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/replay", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	worker := launchStorageWorker(t, f)
	f.remote = worker.ready(t)
	f.loginAs(t, visitor.Email, password)
	visitorToken := f.token
	client := uuid.Must(uuid.NewV4()).String()
	stream := f.openPermissionStream(t, uri, client)
	stream.next(t, "subscribed")
	stream.close()
	f.login(t)
	f.upload(t, "cloudreve://my/replay/old-private-name.txt", []byte("was visible"), nil)
	require.Eventually(t, func() bool {
		return f.db.FsEvent.Query().Where(fsevent.UserFsevent(visitor.ID)).CountX(context.Background()) > 0
	}, 5*time.Second, 10*time.Millisecond)
	worker.stop(t)
	f.remote = ""
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/replay/old-private-name.txt"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	worker = launchStorageWorker(t, f)
	f.remote = worker.ready(t)
	f.token = visitorToken
	resumed := f.openPermissionStream(t, uri, client)
	resumed.next(t, "resumed")
	f.login(t)
	f.upload(t, "cloudreve://my/replay/current-visible.txt", []byte("now visible"), nil)
	msg := assertPermissionStreamUntil(t, resumed, "event", "old-private-name.txt")
	require.Contains(t, msg.Data, "current-visible.txt")
	resumed.close()
}

func TestFilePermissionsOfflineHistoryOverflowIsBoundedAndRefreshes(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/overflow/seed.txt", []byte("seed"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/overflow", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	token := f.token
	client := uuid.Must(uuid.NewV4()).String()
	stream := f.openPermissionStream(t, uri, client)
	stream.next(t, "subscribed")
	stream.close()
	f.login(t)
	for i := 0; i < 280; i++ {
		f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": fmt.Sprintf("cloudreve://my/overflow/folder-%03d", i), "type": "folder"}, nil)
	}
	require.Eventually(t, func() bool {
		n := f.db.FsEvent.Query().Where(fsevent.UserFsevent(visitor.ID)).CountX(context.Background())
		return n > 0 && n <= 256
	}, 5*time.Second, 10*time.Millisecond)
	f.token = token
	resumed := f.openPermissionStream(t, uri, client)
	resumed.next(t, "resumed")
	require.Equal(t, "{}", resumed.next(t, "refresh").Data)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri)+"&page_size=1000", nil, &listing)
	require.Len(t, listing.Files, 281)
}

func TestFilePermissionsActiveDuplicateCannotTakeOverStream(t *testing.T) {
	f := newWritableShareFixture(t)
	f.immediatePermissionEvents(t)
	f.upload(t, "cloudreve://my/duplicate/seed.txt", []byte("seed"), nil)
	client := uuid.Must(uuid.NewV4()).String()
	stream := f.openPermissionStream(t, "cloudreve://my/duplicate", client)
	stream.next(t, "subscribed")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v4/file/events?uri="+url.QueryEscape("cloudreve://my/duplicate"), nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set(request.ClientIDHeader, client)
	f.router.ServeHTTP(w, req)
	require.NotZero(t, permissionResponseCode(t, w.Body.Bytes()))
	f.upload(t, "cloudreve://my/duplicate/still-connected.txt", []byte("not stolen"), nil)
	permissionStreamPath(t, stream, "/still-connected.txt")
	stream.close()
	resumed := f.openPermissionStream(t, "cloudreve://my/duplicate", client)
	resumed.next(t, "resumed")
}

func TestFilePermissionsIdleStreamEndsAtNativeTokenExpiry(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/expiry/seed.txt", []byte("seed"), nil)
	require.NoError(t, f.db.Setting.Create().SetName("access_token_ttl").SetValue("3600").OnConflictColumns("name").UpdateName().Exec(context.Background()))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"access_token_ttl": "2"}}, nil)
	f.login(t)
	stream := f.openPermissionStream(t, "cloudreve://my/expiry", "")
	stream.next(t, "subscribed")
	select {
	case <-stream.ended:
	case <-time.After(4 * time.Second):
		t.Fatal("idle stream outlived its native access token")
	}
}
