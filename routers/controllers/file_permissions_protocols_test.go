package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	settingsvc "github.com/cloudreve/Cloudreve/v4/service/setting"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsWebDAVUsesOriginalShareAndCurrentACL(t *testing.T) {
	f := newWritableShareFixture(t)
	g := f.db.Group.GetX(context.Background(), 2)
	boolset.Set(types.GroupPermissionWebDAV, true, g.Permissions)
	boolset.Set(types.GroupPermissionWebDAVProxy, true, g.Permissions)
	require.NoError(t, f.db.Group.UpdateOne(g).SetPermissions(g.Permissions).Exec(context.Background()))
	f.upload(t, "cloudreve://my/dav-share/file.txt", []byte("DAV original"), nil)
	id, share := f.createWritableShare(t, "cloudreve://my/dav-share", map[string]any{"everyone": "Lw=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var account, readonly settingsvc.DavAccount
	f.request(t, http.MethodPut, "/api/v4/devices/dav", map[string]any{"uri": share, "name": "share DAV", "proxy": true}, &account)
	f.request(t, http.MethodPut, "/api/v4/devices/dav", map[string]any{"uri": share, "name": "readonly share DAV", "proxy": true, "readonly": true}, &readonly)
	w := f.binaryRequest(t, http.MethodGet, "/dav/file.txt", nil, visitor.Email, account.Password)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, []byte("DAV original"), w.Body.Bytes())
	w = f.binaryRequest(t, http.MethodPut, "/dav/new.txt", []byte("DAV created"), visitor.Email, account.Password)
	require.Less(t, w.Code, 300)
	w = f.binaryRequest(t, http.MethodPut, "/dav/file.txt", []byte("DAV replaced"), visitor.Email, account.Password)
	require.Less(t, w.Code, 300)
	w = f.binaryRequest(t, http.MethodPut, "/dav/forbidden.txt", []byte("denied"), visitor.Email, readonly.Password)
	require.GreaterOrEqual(t, w.Code, 400)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/dav-share/new.txt"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	w = f.binaryRequest(t, http.MethodGet, "/dav/new.txt", nil, visitor.Email, account.Password)
	require.GreaterOrEqual(t, w.Code, 400)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/dav-share", "permissions": map[string]string{"everyone": "IQ=="}}, nil)
	w = f.binaryRequest(t, http.MethodPut, "/dav/file.txt", []byte("old DAV capability"), visitor.Email, account.Password)
	require.GreaterOrEqual(t, w.Code, 400)
	require.Equal(t, []byte("DAV replaced"), f.readFile(t, "cloudreve://my/dav-share/file.txt"))
	f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
	w = f.binaryRequest(t, http.MethodGet, "/dav/file.txt", nil, visitor.Email, account.Password)
	require.GreaterOrEqual(t, w.Code, 400)
}

func TestFilePermissionsWOPIOldSessionRechecksReadAndWrite(t *testing.T) {
	f := newWritableShareFixture(t)
	uri := "cloudreve://my/office/file.txt"
	f.upload(t, uri, []byte("Office original"), nil)
	info := f.fileInfo(t, uri)
	id, share := f.createWritableShare(t, "cloudreve://my/office", map[string]any{"everyone": "Lw=="})
	raw, err := json.Marshal([]types.ViewerGroup{{Viewers: []types.Viewer{{ID: "controlled-office", Type: types.ViewerTypeWopi, DisplayName: "Controlled office", Exts: []string{"txt"}, WopiActions: map[string]map[types.ViewerAction]string{"txt": {types.ViewerActionEdit: "https://office.invalid/edit", types.ViewerActionView: "https://office.invalid/view"}}}}}})
	require.NoError(t, err)
	viewer := string(raw)
	require.NoError(t, f.db.Setting.Create().SetName("file_viewers").SetValue("[]").OnConflictColumns("name").UpdateName().Exec(context.Background()))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"file_viewers": viewer}}, nil)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var session explorer.ViewerSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/viewerSession", map[string]string{"uri": share + "/file.txt", "viewer_id": "controlled-office", "preferred_action": "edit"}, &session)
	path := "/api/v4/file/wopi/" + info.ID + "?access_token=" + url.QueryEscape(session.Session.AccessToken)
	getInfo := func() explorer.WopiFileInfo {
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, w.Code)
		var result explorer.WopiFileInfo
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		return result
	}
	require.True(t, getInfo().UserCanWrite)
	put := "/api/v4/file/wopi/" + info.ID + "/contents?access_token=" + url.QueryEscape(session.Session.AccessToken)
	w := f.binaryRequest(t, http.MethodPost, put, []byte("Office legitimate save"), "", "")
	require.Equal(t, http.StatusOK, w.Code)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/office", "permissions": map[string]string{"everyone": "IQ=="}}, nil)
	require.False(t, getInfo().UserCanWrite)
	w = f.binaryRequest(t, http.MethodPost, put, []byte("stale edit"), "", "")
	require.GreaterOrEqual(t, w.Code, 400)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/office", "permissions": map[string]string{"everyone": "AA=="}}, nil)
	w = f.binaryRequest(t, http.MethodGet, "/api/v4/file/wopi/"+info.ID+"/contents?access_token="+url.QueryEscape(session.Session.AccessToken), nil, "", "")
	require.GreaterOrEqual(t, w.Code, 400)
	require.Equal(t, []byte("Office legitimate save"), f.readFile(t, uri))
}

func TestFilePermissionsArchiveRejectsHiddenAndQueuedRevokedSources(t *testing.T) {
	f := newWritableShareFixture(t)
	f.enableArchive(t)
	f.upload(t, "cloudreve://my/archive-source/visible.txt", []byte("visible bytes"), nil)
	f.upload(t, "cloudreve://my/archive-source/hidden/private.txt", []byte("private bytes"), nil)
	f.upload(t, "cloudreve://my/archive-output/seed.txt", []byte("seed"), nil)
	id, share := f.createWritableShare(t, "cloudreve://my/archive-source", map[string]any{"everyone": "IQ=="})
	_, dst := f.createWritableShare(t, "cloudreve://my/archive-output", map[string]any{"everyone": "Lw=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/archive-source/hidden"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{share}, "dst": dst + "/denied.zip"}))
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/archive-source/hidden"}}, nil)
	f.loginAs(t, visitor.Email, password)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{share + "/visible.txt"}, "dst": dst + "/queued.zip"}, &accepted)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/archive-source", "permissions": map[string]string{"everyone": "AA=="}}, nil)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.loginAs(t, visitor.Email, password)
	f.waitForStorageTask(t, accepted.ID, "error")
	f.remote = ""
	f.login(t)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/archive-output/queued.zip"), nil))
	require.Equal(t, []byte("private bytes"), f.readFile(t, "cloudreve://my/archive-source/hidden/private.txt"))
	w.stop(t)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/archive-source", "permissions": map[string]string{"everyone": "IQ=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{share + "/visible.txt"}, "dst": dst + "/valid.zip"}, &accepted)
	w = launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	f.remote = ""
	f.login(t)
	require.NotEmpty(t, f.readFile(t, "cloudreve://my/archive-output/valid.zip"))
}
