package controllers_test

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/url"
	"path"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationIncludesOwnerThumbnailAndLivePhoto(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	token := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	permissions, err := boolset.FromString(group["permissions"].(string))
	require.NoError(t, err)
	boolset.Set(int(types.GroupPermissionShare), true, permissions)
	boolset.Set(int(types.GroupPermissionShareDownload), true, permissions)
	group["permissions"] = permissions
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = token
	settings := *f.policies[0].Settings
	settings.ThumbGeneratorProxy = true
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetSettings(&settings).Save(context.Background())
	require.NoError(t, err)
	viewerPermissions := &boolset.BooleanSet{}
	boolset.Set(int(types.GroupPermissionShareDownload), true, viewerPermissions)
	_, err = f.db.Group.UpdateOneID(3).SetStoragePolicyID(f.policies[1].ID).SetPermissions(viewerPermissions).Save(context.Background())
	require.NoError(t, err)
	viewerPassword := storageRandom(t)
	_, err = inventory.NewUserClient(f.db).Create(context.Background(), &inventory.NewUserArgs{Email: "storage-viewer@example.com", PlainPassword: viewerPassword, GroupID: 3, Status: user.StatusActive, SkipBootstrap: true})
	require.NoError(t, err)
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x * 4), G: uint8(y * 4), B: 64, A: 255})
		}
	}
	var encoded bytes.Buffer
	require.NoError(t, png.Encode(&encoded, img))
	uri := "cloudreve://my/photo.png"
	f.upload(t, uri, encoded.Bytes(), nil)
	live := []byte("actual retained Live Photo companion bytes")
	var liveSession explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(live), "entity_type": "live_photo"}, &liveSession)
	f.finishUpload(t, liveSession, live)
	var shareLink string
	f.request(t, http.MethodPost, "/api/v4/share", map[string]any{"uri": uri}, &shareLink)
	link, err := url.Parse(shareLink)
	require.NoError(t, err)
	shared := fs.NewShareUri(path.Base(link.Path), "") + "/photo.png"
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.loginAs(t, "storage-viewer@example.com", viewerPassword)
	var preview explorer.FileThumbResponse
	f.request(t, http.MethodGet, "/api/v4/file/thumb?uri="+url.QueryEscape(shared), nil, &preview)
	_, thumbBefore := storageHTTP(t, http.MethodGet, preview.Url, nil)
	_, err = png.Decode(bytes.NewReader(thumbBefore))
	if err != nil {
		_, _, err = image.Decode(bytes.NewReader(thumbBefore))
	}
	require.NoError(t, err)
	f.login(t)
	before := f.fileInfo(t, uri)
	require.Len(t, before.ExtendedInfo.Entities, 3)
	models := map[string]*ent.Entity{}
	for _, e := range before.ExtendedInfo.Entities {
		id, err := f.dep.HashIDEncoder().Decode(e.ID, hashid.EntityID)
		require.NoError(t, err)
		models[e.ID], err = f.db.Entity.Get(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, 2, models[e.ID].CreatedBy, "read-only viewer does not own the generated Entity")
		require.Equal(t, f.policies[0].ID, models[e.ID].StoragePolicyEntities)
	}
	f.assertObjectCounts(t, 4, 0)
	// Submit in a process whose queue has not started, then restart the native
	// worker to discover the complete three-entity command.
	worker.stop(t)
	f.remote = ""
	f.login(t)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Len(t, after.ExtendedInfo.Entities, 3)
	for _, e := range after.ExtendedInfo.Entities {
		require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), e.StoragePolicy.ID)
		id, err := f.dep.HashIDEncoder().Decode(e.ID, hashid.EntityID)
		require.NoError(t, err)
		current, err := f.db.Entity.Get(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, models[e.ID].Type, current.Type)
		require.Equal(t, models[e.ID].CreatedAt, current.CreatedAt)
		require.Equal(t, models[e.ID].CreatedBy, current.CreatedBy)
		var links explorer.FileURLResponse
		f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}, "entity": e.ID}, &links)
		_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
		switch types.EntityType(current.Type) {
		case types.EntityTypeVersion:
			require.Equal(t, encoded.Bytes(), data)
		case types.EntityTypeThumbnail:
			require.Equal(t, thumbBefore, data)
		case types.EntityTypeLivePhoto:
			require.Equal(t, live, data)
		default:
			t.Fatal("unexpected planned media entity")
		}
	}
	f.request(t, http.MethodGet, "/api/v4/file/thumb?uri="+url.QueryEscape(uri), nil, &preview)
	_, thumbAfter := storageHTTP(t, http.MethodGet, preview.Url, nil)
	require.Equal(t, thumbBefore, thumbAfter)
	f.assertObjectCounts(t, 4, 3)
}
