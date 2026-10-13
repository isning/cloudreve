package controllers_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageExclusiveFileRelocatesToSecondBucketAtFullQuota(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/migrate.txt"
	data := bytes.Repeat([]byte("physical migration preserves raw content\n"), 257)
	f.upload(t, uri, data, nil)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	memberToken := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["max_storage"] = capacityBefore.Used
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = memberToken
	before := f.fileInfo(t, uri)
	entityID, err := f.dep.HashIDEncoder().Decode(before.ExtendedInfo.Entities[0].ID, hashid.EntityID)
	require.NoError(t, err)
	entityBefore, err := f.db.Entity.Get(context.Background(), entityID)
	require.NoError(t, err)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": b}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.UpdatedAt, after.UpdatedAt)
	require.Equal(t, before.CreatedAt, after.CreatedAt)
	require.Equal(t, before.Size, after.Size)
	require.Len(t, after.ExtendedInfo.Entities, 1)
	require.Equal(t, before.ExtendedInfo.Entities[0].ID, after.ExtendedInfo.Entities[0].ID)
	require.Equal(t, before.ExtendedInfo.Entities[0].CreatedAt, after.ExtendedInfo.Entities[0].CreatedAt)
	entityAfter, err := f.db.Entity.Get(context.Background(), entityID)
	require.NoError(t, err)
	require.Equal(t, entityBefore.UpdatedAt, entityAfter.UpdatedAt)
	require.Equal(t, b, after.ExtendedInfo.Entities[0].StoragePolicy.ID)
	require.Equal(t, before.ExtendedInfo.StoragePolicy.ID, after.ExtendedInfo.StoragePolicy.ID, "future preference remains A")
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}}, &links)
	require.Len(t, links.Urls, 1)
	require.True(t, strings.Contains(links.Urls[0].Url, f.policies[1].BucketName), "new content URL must resolve the committed target bucket")
	require.Equal(t, data, f.readFile(t, uri))
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	f.assertObjectCounts(t, 2, 1)
	jobID, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	item, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(jobID)).Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, relocationitem.StateCommitted, item.State)
	require.Equal(t, relocationitem.SourceCleanupPending, item.SourceCleanup)
	attempt, err := item.QueryAttempts().Only(context.Background())
	require.NoError(t, err)
	require.True(t, attempt.Verified)
	require.EqualValues(t, len(data), attempt.VerifiedSize)
	require.NotEmpty(t, attempt.VerifiedDigest)
	require.Equal(t, relocationattempt.IoStateEnded, attempt.IoState)
	require.Equal(t, relocationattempt.CleanupRetained, attempt.Cleanup)
}

func TestStorageRelocationNewReferenceDuringPutFailsSafely(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	memberToken := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["settings"] = map[string]any{"max_walked_files": 10000}
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = memberToken
	src := "cloudreve://my/race.txt"
	data := []byte("a newly copied reference must retain readable source")
	f.upload(t, src, data, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/copies", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/selected", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{src}, "dst": "cloudreve://my/selected", "copy": true}, nil)
	before := f.fileInfo(t, src)

	backend, err := url.Parse(f.policies[1].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	started, release := make(chan struct{}), make(chan struct{})
	var startOnce, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") {
			startOnce.Do(func() { close(started) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		server.Close()
	})
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Save(context.Background())
	require.NoError(t, err)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{src, "cloudreve://my/selected/race.txt"}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	f.remote = w.ready(t)
	f.login(t)
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("destination PUT did not start")
	}
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{src}, "dst": "cloudreve://my/copies", "copy": true}, nil)
	releaseOnce.Do(func() { close(release) })
	f.waitForStorageTask(t, accepted.ID, "error")
	require.Equal(t, data, f.readFile(t, src))
	require.Equal(t, data, f.readFile(t, "cloudreve://my/selected/race.txt"))
	require.Equal(t, before.PrimaryEntity, f.fileInfo(t, src).PrimaryEntity)
	id, err := f.dep.HashIDEncoder().Decode(before.PrimaryEntity, hashid.EntityID)
	require.NoError(t, err)
	current, err := f.db.Entity.Query().Where(entity.ID(id)).WithFile().Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, 3, current.ReferenceCount)
	require.Len(t, current.Edges.File, 3)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/copies/race.txt"))
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), f.fileInfo(t, src).ExtendedInfo.Entities[0].StoragePolicy.ID)
	// The failed attempt owns its uploaded object durably until compensation is implemented.
	attempt, err := f.db.RelocationAttempt.Query().Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, relocationattempt.CleanupPending, attempt.Cleanup)
	require.NotEmpty(t, attempt.TargetKey)
}
