package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestAuditActivityRedactsHiddenHistoricalPaths(t *testing.T) {
	for _, copying := range []bool{true, false} {
		t.Run(fmt.Sprintf("copy=%v", copying), func(t *testing.T) {
			f := newWritableShareFixture(t)
			root := "cloudreve://my/history-review"
			source := root + "/hidden-parent-marker/report.txt"
			f.upload(t, source, []byte("private origin"), nil)
			f.upload(t, root+"/public/control.txt", []byte("visible control"), nil)
			_, share := f.createWritableShare(t, root, map[string]any{"everyone": "Lw=="})
			f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{root + "/hidden-parent-marker"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
			f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{source}, "dst": root + "/public", "copy": copying}, nil)
			visitor, password := f.createWritableVisitor(t, 2)
			f.loginAs(t, visitor.Email, password)
			require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(share+"/hidden-parent-marker"), nil))
			var response explorer.FileActivitiesResponse
			f.request(t, http.MethodGet, "/api/v4/file/activities?page_size=100&uri="+url.QueryEscape(share+"/public/report.txt"), nil, &response)
			expected := types.AuditMoveTo
			if copying {
				expected = types.AuditCopyTo
			}
			found := false
			for _, activity := range response.Activities {
				if activity.Content.Category == expected {
					found = true
					require.Equal(t, "redacted", activity.Content.From)
				}
			}
			require.True(t, found, "the visible object's operation remains available")
			raw, err := json.Marshal(response)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "hidden-parent-marker")
			f.request(t, http.MethodGet, "/api/v4/file/activities?page_size=100&uri="+url.QueryEscape(share+"/public/control.txt"), nil, &response)
			visible := false
			for _, activity := range response.Activities {
				if activity.Content.From == share+"/public/control.txt" {
					visible = true
				}
			}
			require.True(t, visible, "a currently authorized reference to the same object remains displayable")
		})
	}
}

func TestAuditUploadCancellationRetainsRequestActor(t *testing.T) {
	for _, anonymous := range []bool{true, false} {
		t.Run(fmt.Sprintf("anonymous=%v", anonymous), func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.upload(t, "cloudreve://my/cancel-review/existing.txt", []byte("keep"), nil)
			_, share := f.createWritableShare(t, "cloudreve://my/cancel-review", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
			actor := 0
			if anonymous {
				f.token = ""
			} else {
				visitor, password := f.createWritableVisitor(t, 2)
				actor = visitor.ID
				f.loginAs(t, visitor.Email, password)
			}
			var upload explorer.UploadSessionResponse
			uri := share + "/cancelled.txt"
			f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": 32}, &upload)
			pending, err := f.db.File.Query().Where(file.Name("cancelled.txt")).Only(context.Background())
			require.NoError(t, err)
			f.request(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"uri": uri, "id": upload.SessionID}, nil)
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			var response struct {
				Logs []struct {
					UserID int `json:"user_id"`
				} `json:"logs"`
			}
			f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 20, "conditions": map[string]string{"audit_log_file": fmt.Sprint(pending.ID), "audit_log_category": fmt.Sprint(types.AuditDeleteFile)}}, &response)
			require.Len(t, response.Logs, 1)
			require.Equal(t, actor, response.Logs[0].UserID, "execution as owner must not replace the original request actor")
			f.login(t)
			require.Equal(t, []byte("keep"), f.readFile(t, "cloudreve://my/cancel-review/existing.txt"))
			require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/cancel-review/cancelled.txt"), nil))
		})
	}
}

func TestAuditActivityRedactsHiddenHistoricalRename(t *testing.T) {
	f := newWritableShareFixture(t)
	root := "cloudreve://my/rename-history-review"
	f.upload(t, root+"/private/secret-project-marker.txt", []byte("private"), nil)
	f.upload(t, root+"/public/control.txt", []byte("control"), nil)
	_, share := f.createWritableShare(t, root, map[string]any{"everyone": "Lw=="})
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{root + "/private"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": root + "/private/secret-project-marker.txt", "new_name": "public.txt"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{root + "/private/public.txt"}, "dst": root + "/public", "copy": false}, nil)
	var response explorer.FileActivitiesResponse
	endpoint := "/api/v4/file/activities?page_size=100&uri="
	f.request(t, http.MethodGet, endpoint+url.QueryEscape(root+"/public/public.txt"), nil, &response)
	ownerHistory, err := json.Marshal(response)
	require.NoError(t, err)
	require.Contains(t, string(ownerHistory), "secret-project-marker.txt")
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	response = explorer.FileActivitiesResponse{}
	f.request(t, http.MethodGet, endpoint+url.QueryEscape(share+"/public/public.txt"), nil, &response)
	raw, err := json.Marshal(response)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secret-project-marker.txt")
	found := false
	for _, activity := range response.Activities {
		if activity.Content.Category == types.AuditFileRename {
			found = true
		}
	}
	require.True(t, found, "event remains available without historical secret names")
}
