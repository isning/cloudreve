package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	settingsvc "github.com/cloudreve/Cloudreve/v4/service/setting"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) binaryRequest(t *testing.T, method, path string, data []byte, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := httptest.NewRequest(method, path, bytes.NewReader(data)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))
	if username != "" {
		req.SetBasicAuth(username, password)
	} else if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *storageFixture) fileInfo(t *testing.T, uri string) explorer.FileResponse {
	t.Helper()
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	return info
}

func TestStorageEditorSaveUsesFilePreferenceAndRevokedFallback(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	_, err := f.db.User.UpdateOneID(2).SetSettings(&types.UserSetting{VersionRetention: true, VersionRetentionMax: 10}).Save(context.Background())
	require.NoError(t, err)
	uri := "cloudreve://my/parent/editor.txt"
	original := []byte("original editor content on A")
	f.upload(t, uri, original, nil)
	initial := f.fileInfo(t, uri)
	f.bindFolder(t, "cloudreve://my/parent", 1)
	save := func(data []byte) {
		t.Helper()
		current := f.fileInfo(t, uri)
		w := f.binaryRequest(t, http.MethodPut, "/api/v4/file/content?uri="+url.QueryEscape(uri)+"&previous="+current.PrimaryEntity, data, "", "")
		var result struct {
			Code int                   `json:"code"`
			Data explorer.FileResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		require.Zero(t, result.Code)
		require.Equal(t, initial.ID, result.Data.ID)
		require.Equal(t, data, f.readFile(t, uri))
	}
	updated := []byte("editor respects file A despite parent B")
	save(updated)
	info := f.fileInfo(t, uri)
	require.Len(t, info.ExtendedInfo.Entities, 2)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	for _, entity := range info.ExtendedInfo.Entities {
		require.Equal(t, a, entity.StoragePolicy.ID)
	}
	f.assignPolicies(t, f.policies[1].ID)
	fallback := []byte("editor fallback to current first B")
	save(fallback)
	info = f.fileInfo(t, uri)
	require.Len(t, info.ExtendedInfo.Entities, 3)
	for _, entity := range info.ExtendedInfo.Entities {
		if entity.ID == info.PrimaryEntity {
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), entity.StoragePolicy.ID)
		}
	}
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(original)+len(updated)+len(fallback), capacity.Used)
	f.token = ""
	w := f.binaryRequest(t, http.MethodPut, "/api/v4/file/content?uri="+url.QueryEscape(uri), []byte("unauthenticated"), "", "")
	var rejected storageResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rejected))
	require.Equal(t, serializer.CodeCheckLogin, rejected.Code)
}

func TestStorageWebDAVCreatesAndUpdatesWithNativePolicyRules(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	permission := &boolset.BooleanSet{}
	boolset.Set(types.GroupPermissionWebDAV, true, permission)
	boolset.Set(types.GroupPermissionWebDAVProxy, true, permission)
	group["permissions"] = permission
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.login(t)
	_, err := f.db.User.UpdateOneID(2).SetSettings(&types.UserSetting{VersionRetention: true, VersionRetentionMax: 10}).Save(context.Background())
	require.NoError(t, err)
	uri := "cloudreve://my/parent/existing.txt"
	original := []byte("initial file A before parent binding")
	f.upload(t, uri, original, nil)
	f.bindFolder(t, "cloudreve://my/parent", 1)
	var account settingsvc.DavAccount
	f.request(t, http.MethodPut, "/api/v4/devices/dav", map[string]any{"uri": "cloudreve://my/parent", "name": "Owned integration DAV", "proxy": true}, &account)
	require.NotEmpty(t, account.Password)
	request := func(method, path string, data []byte) *httptest.ResponseRecorder {
		return f.binaryRequest(t, method, "/dav"+path, data, "storage@example.com", account.Password)
	}
	w := request("MKCOL", "/child", nil)
	require.Equal(t, http.StatusCreated, w.Code)
	next := []byte("WebDAV creation inherits B")
	w = request(http.MethodPut, "/child/new.txt", next)
	require.Equal(t, http.StatusCreated, w.Code)
	info := f.fileInfo(t, "cloudreve://my/parent/child/new.txt")
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	require.Equal(t, b, info.ExtendedInfo.StoragePolicy.ID)
	w = request(http.MethodGet, "/child/new.txt", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, next, w.Body.Bytes())
	update := []byte("WebDAV update preserves file preference A")
	w = request(http.MethodPut, "/existing.txt", update)
	require.Less(t, w.Code, 300)
	info = f.fileInfo(t, uri)
	require.Len(t, info.ExtendedInfo.Entities, 2)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	for _, entity := range info.ExtendedInfo.Entities {
		require.Equal(t, a, entity.StoragePolicy.ID)
	}
	require.Equal(t, update, f.readFile(t, uri))
	f.assignPolicies(t, f.policies[0].ID)
	w = request(http.MethodPut, "/child/after-revoke.txt", []byte("revoked binding B falls back to A"))
	require.Equal(t, http.StatusCreated, w.Code)
	info = f.fileInfo(t, "cloudreve://my/parent/child/after-revoke.txt")
	require.Equal(t, a, info.ExtendedInfo.StoragePolicy.ID)
	w = request(http.MethodGet, "/child/new.txt", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, next, w.Body.Bytes(), "old B content remains readable after revoke")
	w = f.binaryRequest(t, http.MethodPut, "/dav/child/forged.txt", []byte("wrong credential"), "storage@example.com", storageRandom(t))
	require.Equal(t, http.StatusUnauthorized, w.Code)
}
