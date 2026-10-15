package controllers_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/routers"
	"github.com/stretchr/testify/require"
)

func newAuditFixture(t *testing.T) *storageFixture {
	t.Helper()
	f := newStorageFixture(t)
	for _, g := range mustAuditGroups(t, f) {
		settings := g.Settings
		if settings == nil {
			settings = &types.GroupSetting{}
		}
		settings.MaxWalkedFiles = 1000
		_, err := f.db.Group.UpdateOneID(g.ID).SetSettings(settings).Save(context.Background())
		require.NoError(t, err)
	}
	require.NoError(t, inventory.EnsureAuditSchema(context.Background(), f.db))
	f.router = routers.InitRouter(f.dep)
	return f
}

func TestAuditSharesAndUserChangesRecordActorsWithoutExposingHistoryToReaders(t *testing.T) {
	f := newAuditFixture(t)
	g, err := f.db.Group.Get(context.Background(), 2)
	require.NoError(t, err)
	boolset.Set(types.GroupPermissionShare, true, g.Permissions)
	_, err = f.db.Group.UpdateOneID(2).SetPermissions(g.Permissions).Save(context.Background())
	require.NoError(t, err)
	f.login(t)
	f.upload(t, "cloudreve://my/shared-history.txt", []byte("share audit"), nil)
	var link string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/shared-history.txt"}, &link)
	u, err := url.Parse(link)
	require.NoError(t, err)
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	id := parts[len(parts)-1]
	f.token = ""
	f.request(t, http.MethodGet, "/api/v4/share/info/"+id+"?count_views=true", nil, nil)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/activities?uri="+url.QueryEscape(fs.NewShareUri(id, ""))+"&page_size=20", nil))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/activities?uri="+url.QueryEscape(fs.NewShareUri(id, ""))+"&page_size=20", nil), "a read-only share does not grant history, even to a separately authenticated viewer")
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/shared-history.txt", "downloads": 10}, nil)
	f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
	f.request(t, http.MethodPatch, "/api/v4/user/setting", map[string]string{"nick": "Audited nickname"}, nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var logs struct {
		Logs []struct {
			Type    int            `json:"type"`
			FileID  int            `json:"file_id"`
			UserID  int            `json:"user_id"`
			Content map[string]any `json:"content"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "17,18,24,25,46"}}, &logs)
	seen := map[int]bool{}
	for _, log := range logs.Logs {
		seen[log.Type] = true
		if log.Type == 46 {
			require.Equal(t, map[string]any{"from": "storage", "to": "Audited nickname"}, log.Content["exts"], "the Pro nickname renderer consumes exts.from/to")
		}
		if log.Type != 18 {
			require.Equal(t, 2, log.UserID)
		}
		if log.Type != 46 {
			require.Positive(t, log.FileID)
		}
		require.NotContains(t, log.Content, "password")
	}
	for _, event := range []int{17, 18, 24, 25, 46} {
		require.True(t, seen[event], "missing event %d", event)
	}
	// Administrative file filters continue to use historical numeric or hash IDs.
	var all struct {
		Logs []map[string]any `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 20, "conditions": map[string]string{"audit_log_user": hashid.EncodeUserID(f.dep.HashIDEncoder(), 2)}}, &all)
	require.NotEmpty(t, all.Logs)
}

func TestAuditMutationRollsBackIfItsDurableRecordCannotBeWritten(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/atomic.txt", []byte("atomic"), nil)
	f.db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if kind, ok := m.Field("type"); ok && kind == 8 {
				return nil, errors.New("injected audit write failure")
			}
			return next.Mutate(ctx, m)
		})
	})
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": "cloudreve://my/atomic.txt", "new_name": "must-not-exist.txt"}))
	info := f.fileInfo(t, "cloudreve://my/atomic.txt")
	require.Equal(t, "atomic.txt", info.Name)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/must-not-exist.txt"), nil))
}

func TestAuditAdministrativeFileChangesRetainTheActualAdministrator(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/admin-edited.txt", []byte("admin audit"), nil)
	info := f.fileInfo(t, "cloudreve://my/admin-edited.txt")
	id, err := f.dep.HashIDEncoder().Decode(info.ID, hashid.FileID)
	require.NoError(t, err)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var detail map[string]any
	f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/file/%d", id), nil, &detail)
	detail["name"] = "admin-renamed.txt"
	f.request(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/file/%d", id), map[string]any{"file": detail}, nil)
	f.request(t, http.MethodPost, "/api/v4/admin/file/batch/delete", map[string]any{"ids": []int{id}}, nil)
	var result struct {
		Logs []struct {
			Type   int `json:"type"`
			UserID int `json:"user_id"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_file": fmt.Sprint(id), "audit_log_category": "8,15,23"}}, &result)
	seen := map[int]bool{}
	for _, event := range result.Logs {
		seen[event.Type] = true
		require.Equal(t, 1, event.UserID)
	}
	for _, event := range []int{8, 15, 23} {
		require.True(t, seen[event])
	}
}

func TestAuditRemovedVersionsLoseTheirActivityLinks(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	uri := "cloudreve://my/versions.txt"
	f.upload(t, uri, []byte("first version"), nil)
	first := f.fileInfo(t, uri)
	w := f.binaryRequest(t, http.MethodPut, "/api/v4/file/content?uri="+url.QueryEscape(uri)+"&previous="+first.PrimaryEntity, []byte("second version"), "", "")
	var saved struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &saved))
	require.Zero(t, saved.Code)
	f.request(t, http.MethodDelete, "/api/v4/file/version", map[string]string{"uri": uri, "version": first.PrimaryEntity}, nil)
	var result struct {
		Activities []struct {
			Content struct {
				Category int `json:"category"`
			} `json:"content"`
			Version string `json:"version_id"`
		} `json:"activities"`
	}
	f.request(t, http.MethodGet, "/api/v4/file/activities?uri="+url.QueryEscape(uri)+"&page_size=20", nil, &result)
	removed, live, deleted := 0, 0, false
	for _, activity := range result.Activities {
		if activity.Content.Category == 10 {
			if activity.Version == "" {
				removed++
			} else {
				live++
				require.NotEqual(t, first.PrimaryEntity, activity.Version)
			}
		}
		if activity.Content.Category == 20 {
			deleted = true
		}
	}
	require.Equal(t, 1, removed)
	require.Equal(t, 1, live)
	require.True(t, deleted)
}

func TestAuditConfigurationDisablesEventsAndIPsAndRejectsMalformedSettings(t *testing.T) {
	f := newAuditFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	for _, settings := range []map[string]string{{"audit_enabled_flags": "invalid"}, {"audit_record_ip": "true"}, {"audit_enabled_flags": "//////////8="}} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": settings}))
	}
	flags := &boolset.BooleanSet{}
	boolset.Set(5, true, flags)
	encoded, err := flags.String()
	require.NoError(t, err)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"audit_enabled_flags": encoded, "audit_record_ip": "0"}}, nil)
	f.login(t)
	f.upload(t, "cloudreve://my/not-recorded.txt", []byte("disabled events"), nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var logs struct {
		Logs []struct {
			Type int    `json:"type"`
			IP   string `json:"ip"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "7,10"}}, &logs)
	require.Empty(t, logs.Logs)
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "order_direction": "desc", "conditions": map[string]string{"audit_log_category": "5"}}, &logs)
	require.GreaterOrEqual(t, len(logs.Logs), 2)
	require.Empty(t, logs.Logs[0].IP)
	require.Empty(t, logs.Logs[1].IP)
}

func TestAuditAnonymousDirectDownloadDoesNotImpersonateTheOwner(t *testing.T) {
	f := newAuditFixture(t)
	g, err := f.db.Group.Get(context.Background(), 2)
	require.NoError(t, err)
	g.Settings.SourceBatchSize = 10
	g.Settings.RedirectedSource = true
	_, err = f.db.Group.UpdateOneID(2).SetSettings(g.Settings).Save(context.Background())
	require.NoError(t, err)
	f.login(t)
	f.upload(t, "cloudreve://my/direct.txt", []byte("anonymous download"), nil)
	var links []struct {
		URL string `json:"link"`
	}
	f.request(t, http.MethodPut, "/api/v4/file/source", map[string]any{"uris": []string{"cloudreve://my/direct.txt"}}, &links)
	require.Len(t, links, 1)
	url, err := url.Parse(links[0].URL)
	require.NoError(t, err)
	f.token = ""
	w := f.binaryRequest(t, http.MethodGet, url.RequestURI(), nil, "", "")
	require.Equal(t, http.StatusFound, w.Code)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var result struct {
		Logs []struct {
			UserID int `json:"user_id"`
			FileID int `json:"file_id"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "11", "audit_log_user": "0"}}, &result)
	require.Len(t, result.Logs, 1)
	require.Zero(t, result.Logs[0].UserID)
	require.Positive(t, result.Logs[0].FileID)
}

func TestAuditFileOperationsSurviveMovesAndDeletion(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/source.txt", []byte("history"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/folder", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source.txt"}, "dst": "cloudreve://my/folder", "copy": true}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": "cloudreve://my/folder/source.txt", "new_name": "copy.txt"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source.txt"}, "dst": "cloudreve://my/folder", "copy": false}, nil)
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/folder/source.txt"}, "skip_soft_delete": true}, nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var result struct {
		Logs []struct {
			Type   int `json:"type"`
			FileID int `json:"file_id"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "12,13,14,15"}}, &result)
	seen := map[int]bool{}
	for _, row := range result.Logs {
		seen[row.Type] = true
		require.Positive(t, row.FileID)
	}
	for _, event := range []int{12, 13, 14, 15} {
		require.True(t, seen[event], "missing durable operation %d", event)
	}
}

func TestAuditAdminDeletionAndCleanupAreBounded(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/kept.txt", []byte("keep"), nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var result struct {
		Logs []struct {
			ID   int `json:"id"`
			Type int `json:"type"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "7,10"}}, &result)
	require.Len(t, result.Logs, 2)
	f.request(t, http.MethodPost, "/api/v4/admin/event/batch/delete", map[string]any{"ids": []int{result.Logs[0].ID}}, nil)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/admin/event/"+fmt.Sprint(result.Logs[0].ID), nil))
	f.request(t, http.MethodPost, "/api/v4/admin/event/cleanup", map[string]any{"not_after": time.Now().Add(time.Minute), "categories": []int{result.Logs[1].Type}}, nil)
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "7,10"}}, &result)
	require.Empty(t, result.Logs)
	f.login(t)
	f.request(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/kept.txt"), nil, nil)
}

func TestAuditNativeLoginIsQueryableThroughProAdministrationAPI(t *testing.T) {
	f := newAuditFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	flags := &boolset.BooleanSet{}
	boolset.Set(5, true, flags)
	encoded, err := flags.String()
	require.NoError(t, err)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{
		"audit_enabled_flags": encoded,
		"audit_record_ip":     "1",
	}}, nil)
	f.login(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var result struct {
		Logs []struct {
			ID      int `json:"id"`
			Type    int `json:"type"`
			Content struct {
				Category int `json:"category"`
			} `json:"content"`
			Edges struct {
				User *struct {
					Email string `json:"email"`
				} `json:"user"`
			} `json:"edges"`
		} `json:"logs"`
		Pagination struct {
			Total int `json:"total_items"`
		} `json:"pagination"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{
		"page": 1, "page_size": 20, "order_by": "id", "order_direction": "desc",
		"conditions": map[string]string{"audit_log_category": "5"},
	}, &result)
	require.GreaterOrEqual(t, result.Pagination.Total, 2)
	memberFound := false
	for _, log := range result.Logs {
		require.Positive(t, log.ID)
		require.Equal(t, 5, log.Type)
		require.Equal(t, 5, log.Content.Category)
		if log.Edges.User != nil && log.Edges.User.Email == "storage@example.com" {
			memberFound = true
		}
	}
	require.True(t, memberFound, "successful native login is recorded with its actual actor")
}

func TestAuditRetainsExplicitProviderZeroForFailedOpenIDLogin(t *testing.T) {
	f := newAuditFixture(t)
	f.token = ""
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/session/openid", map[string]any{"provider_id": 0, "code": "invalid-test-code", "session_id": "missing-test-state"}))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var result struct {
		Logs []struct {
			Content struct {
				Provider *int `json:"openid_provider"`
			} `json:"content"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 20, "conditions": map[string]string{"audit_log_category": "4"}}, &result)
	require.Len(t, result.Logs, 1)
	require.NotNil(t, result.Logs[0].Content.Provider)
	require.Zero(t, *result.Logs[0].Content.Provider)
}

func TestAuditFileActivitiesFollowCommittedFileAndRedactAdministrativeData(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/before.txt", []byte("audited object"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": "cloudreve://my/before.txt", "new_name": "after.txt"}, nil)
	var result struct {
		Activities []struct {
			ID        string         `json:"id"`
			Content   map[string]any `json:"content"`
			VersionID string         `json:"version_id"`
			User      map[string]any `json:"user"`
		} `json:"activities"`
		Pagination struct {
			Cursor bool `json:"is_cursor"`
		} `json:"pagination"`
	}
	f.request(t, http.MethodGet, "/api/v4/file/activities?uri="+url.QueryEscape("cloudreve://my/after.txt")+"&page_size=20&order_direction=asc", nil, &result)
	require.True(t, result.Pagination.Cursor)
	categories := map[int]bool{}
	for _, activity := range result.Activities {
		require.NotEmpty(t, activity.ID)
		category := int(activity.Content["category"].(float64))
		categories[category] = true
		if category == 8 {
			require.Equal(t, "before.txt", activity.Content["original_name"])
			require.Equal(t, "after.txt", activity.Content["new_name"])
		}
		if category == 10 {
			require.NotEmpty(t, activity.VersionID)
		}
		require.NotNil(t, activity.User)
		for _, field := range []string{"user_agent", "failed", "error", "account", "sub", "email_to"} {
			require.NotContains(t, activity.Content, field)
		}
	}
	for _, category := range []int{7, 8, 10} {
		require.True(t, categories[category], "missing committed event %d", category)
	}
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(raw), f.password)
	require.NotContains(t, string(raw), `"correlation_id"`)
	require.NotContains(t, string(raw), `"ip"`)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 20}))
}

func mustAuditGroups(t *testing.T, f *storageFixture) []*ent.Group {
	t.Helper()
	groups, err := f.db.Group.Query().All(context.Background())
	require.NoError(t, err)
	return groups
}

func TestAuditArchiveExportsOnlyAuthorizedSnapshotAndPurgesExactRows(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/exported.txt", []byte("export"), nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var archive struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event/archive", map[string]any{"not_before": time.Now().Add(-time.Hour), "not_after": time.Now().Add(time.Hour), "categories": []int{7, 10}}, &archive)
	require.NotEmpty(t, archive.ID)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/event/archive/"+archive.ID, nil), "pending exports cannot delete logs")
	bad := httptest.NewRecorder()
	f.router.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/api/v4/audit/archive/"+archive.ID+"?token=invalid", nil))
	var denied struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(bad.Body.Bytes(), &denied))
	require.NotZero(t, denied.Code)
	f.login(t)
	f.upload(t, "cloudreve://my/later.txt", []byte("retain"), nil)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, archive.URL, nil))
	if w.Header().Get("Content-Type") != "application/gzip" {
		var fail struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fail))
		t.Fatalf("archive download failed: code=%d msg=%s", fail.Code, fail.Msg)
	}
	zip, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	require.NoError(t, err)
	raw, err := io.ReadAll(zip)
	require.NoError(t, err)
	require.NoError(t, zip.Close())
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 2)
	for _, line := range lines {
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		require.NotContains(t, line, f.password)
	}
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var status struct {
		Status string `json:"status"`
	}
	f.request(t, http.MethodGet, "/api/v4/admin/event/archive/"+archive.ID+"/status", nil, &status)
	require.Equal(t, "completed", status.Status)
	f.request(t, http.MethodDelete, "/api/v4/admin/event/archive/"+archive.ID, nil, nil)
	var list struct {
		Logs []map[string]any `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "7,10"}}, &list)
	require.Len(t, list.Logs, 2, "logs created after the export snapshot must survive")
}

type interruptedAuditDownload struct{ *httptest.ResponseRecorder }

func (w *interruptedAuditDownload) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestAuditInterruptedExportCannotAuthorizeDeletion(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/retained.txt", []byte("retain"), nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var archive struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event/archive", map[string]any{"not_before": time.Now().Add(-time.Hour), "not_after": time.Now().Add(time.Hour), "categories": []int{7, 10}}, &archive)
	f.router.ServeHTTP(&interruptedAuditDownload{httptest.NewRecorder()}, httptest.NewRequest(http.MethodGet, archive.URL, nil))
	var status struct {
		Status string `json:"status"`
	}
	f.request(t, http.MethodGet, "/api/v4/admin/event/archive/"+archive.ID+"/status", nil, &status)
	require.Equal(t, "failed", status.Status)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/event/archive/"+archive.ID, nil))
	var result struct {
		Logs []map[string]any `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "7,10"}}, &result)
	require.Len(t, result.Logs, 2)
}

func TestAuditActivityCursorIsStableAuthenticatedAndBoundToFile(t *testing.T) {
	f := newAuditFixture(t)
	f.login(t)
	f.upload(t, "cloudreve://my/page.txt", []byte("pages"), nil)
	f.upload(t, "cloudreve://my/other.txt", []byte("other"), nil)
	name := "page.txt"
	for i := 0; i < 23; i++ {
		next := fmt.Sprintf("page-%d.txt", i)
		f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": "cloudreve://my/" + name, "new_name": next}, nil)
		name = next
	}
	base := "/api/v4/file/activities?uri=" + url.QueryEscape("cloudreve://my/"+name) + "&page_size=10&order_direction=desc"
	var page struct {
		Activities []struct {
			ID      string         `json:"id"`
			Content map[string]any `json:"content"`
		} `json:"activities"`
		Pagination struct {
			Next string `json:"next_token"`
		} `json:"pagination"`
	}
	f.request(t, http.MethodGet, base, nil, &page)
	require.Len(t, page.Activities, 10)
	require.NotEmpty(t, page.Pagination.Next)
	token := page.Pagination.Next
	require.NotZero(t, f.responseCode(t, http.MethodGet, base+"&next_page_token="+url.QueryEscape(token+"x"), nil))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/activities?uri="+url.QueryEscape("cloudreve://my/other.txt")+"&page_size=10&order_direction=desc&next_page_token="+url.QueryEscape(token), nil))
	seen := map[string]bool{}
	for _, event := range page.Activities {
		seen[event.ID] = true
	}
	// A newly committed activity must not shift or duplicate an existing page.
	f.request(t, http.MethodPatch, "/api/v4/file/metadata", map[string]any{"uris": []string{"cloudreve://my/" + name}, "patches": []map[string]any{{"key": "tag:test", "value": "#123456"}}}, nil)
	for token != "" {
		page.Pagination.Next = ""
		f.request(t, http.MethodGet, base+"&next_page_token="+url.QueryEscape(token), nil, &page)
		for _, event := range page.Activities {
			require.False(t, seen[event.ID])
			seen[event.ID] = true
			require.NotEqualValues(t, 23, event.Content["category"])
		}
		token = page.Pagination.Next
	}
	require.Len(t, seen, 25)
}
