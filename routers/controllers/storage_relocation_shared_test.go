package controllers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationSplitsOnlySelectedSharedVersions(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	token := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["settings"] = map[string]any{"max_walked_files": 10000}
	permissions, err := boolset.FromString(group["permissions"].(string))
	require.NoError(t, err)
	boolset.Set(int(types.GroupPermissionShare), true, permissions)
	boolset.Set(int(types.GroupPermissionShareDownload), true, permissions)
	group["permissions"] = permissions
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = token
	src, copyURI := "cloudreve://my/history.txt", "cloudreve://my/copies/history.txt"
	f.upload(t, src, []byte("first shared version"), nil)
	var version explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": src, "size": len("second shared version"), "entity_type": "version"}, &version)
	f.finishUpload(t, version, []byte("second shared version"))
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/copies", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{src}, "dst": "cloudreve://my/copies", "copy": true}, nil)
	var shareLink string
	f.request(t, http.MethodPost, "/api/v4/share", map[string]any{"uri": src}, &shareLink)
	require.NotEmpty(t, shareLink)
	before := f.fileInfo(t, src)
	copyBefore := f.fileInfo(t, copyURI)
	require.Len(t, before.ExtendedInfo.Entities, 2)
	require.Len(t, before.ExtendedInfo.Shares, 1)
	models := map[string]*ent.Entity{}
	contents := map[string][]byte{}
	for _, e := range before.ExtendedInfo.Entities {
		id, err := f.dep.HashIDEncoder().Decode(e.ID, hashid.EntityID)
		require.NoError(t, err)
		model, err := f.db.Entity.Get(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, 2, model.ReferenceCount)
		models[e.ID] = model
		var links explorer.FileURLResponse
		f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{src}, "entity": e.ID}, &links)
		_, contents[e.ID] = storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	}
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	var accepted explorer.TaskResponse
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{src}, "dst_policy_id": b}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	after := f.fileInfo(t, src)
	copyAfter := f.fileInfo(t, copyURI)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.UpdatedAt, after.UpdatedAt)
	require.Equal(t, before.Size, after.Size)
	require.Equal(t, before.ExtendedInfo.Shares[0].ID, after.ExtendedInfo.Shares[0].ID)
	require.Equal(t, shareLink, after.ExtendedInfo.Shares[0].Url)
	require.Len(t, after.ExtendedInfo.Entities, 2)
	require.NotEqual(t, before.PrimaryEntity, after.PrimaryEntity, "only shared Entity identity changes")
	require.Equal(t, copyBefore.PrimaryEntity, copyAfter.PrimaryEntity)
	for _, e := range after.ExtendedInfo.Entities {
		require.Equal(t, b, e.StoragePolicy.ID)
		id, err := f.dep.HashIDEncoder().Decode(e.ID, hashid.EntityID)
		require.NoError(t, err)
		model, err := f.db.Entity.Get(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, 1, model.ReferenceCount)
		var original *ent.Entity
		var oldID string
		for encoded, candidate := range models {
			if candidate.CreatedAt.Equal(model.CreatedAt) {
				original = candidate
				oldID = encoded
			}
		}
		require.NotNil(t, original)
		require.Equal(t, original.Type, model.Type)
		require.Equal(t, original.CreatedBy, model.CreatedBy)
		require.Equal(t, original.CreatedAt, model.CreatedAt)
		for _, uri := range []string{src, copyURI} {
			entityID := e.ID
			if uri == copyURI {
				entityID = oldID
			}
			var links explorer.FileURLResponse
			f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}, "entity": entityID}, &links)
			_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
			require.Equal(t, contents[oldID], data)
		}
		remaining, err := f.db.Entity.Get(context.Background(), original.ID)
		require.NoError(t, err)
		require.Equal(t, original.Source, remaining.Source)
		require.Equal(t, original.StoragePolicyEntities, remaining.StoragePolicyEntities)
		require.Equal(t, 1, remaining.ReferenceCount)
	}
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	f.assertObjectCounts(t, 3, 2)
}
