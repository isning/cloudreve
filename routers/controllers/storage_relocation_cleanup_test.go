package controllers_test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationCompensatesEndedTargetIndependently(t *testing.T) {
	for _, scenario := range []string{"ended_target", "delete_failure_restart", "history_deleted"} {
		t.Run(scenario, func(t *testing.T) {
			retry := scenario != "ended_target"
			historyDeleted := scenario == "history_deleted"
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			payload := []byte("failed target must not replace its intact original")
			failedURI, winningURI := "cloudreve://my/failed.txt", "cloudreve://my/winner.txt"
			f.upload(t, failedURI, payload, nil)
			f.upload(t, winningURI, []byte("winning target stays available"), nil)
			before := f.fileInfo(t, failedURI)
			var capacityBefore fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
			backend, err := url.Parse(f.policies[1].Server)
			require.NoError(t, err)
			proxy := httputil.NewSingleHostReverseProxy(backend)
			var corrupt atomic.Bool
			var deleting atomic.Int32
			var refuseDelete atomic.Bool
			refuseDelete.Store(retry)
			proxy.ModifyResponse = func(res *http.Response) error {
				if res.Request.Method == http.MethodPut && res.StatusCode == http.StatusOK && strings.Contains(res.Request.URL.Path, "/.cloudreve-relocation/") && !corrupt.Swap(true) {
					key := strings.TrimPrefix(res.Request.URL.Path, "/"+f.policies[1].BucketName+"/")
					_, err := f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(key), Body: bytes.NewReader([]byte("corrupt"))})
					return err
				}
				return nil
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deleting.Add(1)
					if refuseDelete.Load() {
						w.Header().Set("Content-Type", "application/xml")
						w.WriteHeader(http.StatusForbidden)
						io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>controlled cleanup failure</Message></Error>")
						return
					}
				}
				proxy.ServeHTTP(w, r)
			}))
			defer server.Close()
			_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Save(context.Background())
			require.NoError(t, err)
			target := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
			var failedJob explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{failedURI}, "dst_policy_id": target}, &failedJob)
			ioWorker := launchStorageWorkerWithWorkflows(t, f)
			f.remote = ioWorker.ready(t)
			f.login(t)
			f.waitForStorageTask(t, failedJob.ID, "error")
			failedID, err := f.dep.HashIDEncoder().Decode(failedJob.ID, hashid.TaskID)
			require.NoError(t, err)
			item, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(failedID)).Only(context.Background())
			require.NoError(t, err)
			failedAttempt, err := item.QueryAttempts().Only(context.Background())
			require.NoError(t, err)
			require.Equal(t, relocationattempt.IoStateEnded, failedAttempt.IoState)
			var winningJob explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{winningURI}, "dst_policy_id": target}, &winningJob)
			f.waitForStorageTask(t, winningJob.ID, "completed")
			f.assertObjectCounts(t, 3, 2)
			if historyDeleted {
				memberToken := f.token
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
				f.request(t, http.MethodPost, "/api/v4/admin/queue/cleanup", map[string]any{"not_after": time.Now().Add(time.Hour), "types": []string{"relocate"}}, nil)
				f.token = memberToken
				n, err := f.db.Task.Query().Where(task.Type("relocate")).Count(context.Background())
				require.NoError(t, err)
				require.Zero(t, n)
			}
			f.recycling = true
			cleaner := launchStorageWorker(t, f)
			_ = cleaner.ready(t)
			if retry {
				require.Eventually(t, func() bool { return deleting.Load() > 0 }, 30*time.Second, 50*time.Millisecond)
				cleaner.stop(t)
				unfinished, err := f.db.RelocationAttempt.Get(context.Background(), failedAttempt.ID)
				require.NoError(t, err)
				require.Equal(t, relocationattempt.CleanupPending, unfinished.Cleanup)
				refuseDelete.Store(false)
				cleaner = launchStorageWorker(t, f)
				_ = cleaner.ready(t)
			}
			require.Eventually(t, func() bool {
				attempt, err := f.db.RelocationAttempt.Get(context.Background(), failedAttempt.ID)
				return err == nil && attempt.Cleanup == relocationattempt.CleanupCleaned
			}, 40*time.Second, 50*time.Millisecond)
			require.Eventually(t, func() bool {
				items, err := f.db.RelocationItem.Query().Where(relocationitem.TaskIDNEQ(failedID)).All(context.Background())
				return err == nil && len(items) == 1 && items[0].SourceCleanup == relocationitem.SourceCleanupCleaned
			}, 40*time.Second, 50*time.Millisecond)
			f.assertObjectCounts(t, 2, 1)
			require.Equal(t, payload, f.readFile(t, failedURI))
			require.Equal(t, []byte("winning target stays available"), f.readFile(t, winningURI))
			after := f.fileInfo(t, failedURI)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
			var capacityAfter fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
			require.Equal(t, capacityBefore, capacityAfter)
			if !historyDeleted {
				f.waitForStorageTask(t, failedJob.ID, "error")
				f.waitForStorageTask(t, winningJob.ID, "completed")
			} else {
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
				endpoint := fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID)
				var original ent.StoragePolicy
				f.request(t, http.MethodGet, endpoint, nil, &original)
				next := original
				next.Server = "http://127.0.0.1:1"
				f.request(t, http.MethodPut, endpoint, map[string]any{"policy": next}, nil)
				f.request(t, http.MethodPut, endpoint, map[string]any{"policy": original}, nil)
			}
			// Maintenance has system ownership, independently of member task history.
			jobs, err := f.db.Task.Query().Where(task.Type("relocation_cleanup")).All(context.Background())
			require.NoError(t, err)
			require.Len(t, jobs, 2)
			for _, job := range jobs {
				require.Zero(t, job.UserTasks)
			}
		})
	}
}

func TestStorageRelocationSourceCleanupRetriesWithoutUndoingCommit(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/source-cleanup.txt"
	payload := []byte("successful destination survives source cleanup refusal")
	f.upload(t, uri, payload, nil)
	before := f.fileInfo(t, uri)
	sourceID, err := f.dep.HashIDEncoder().Decode(before.PrimaryEntity, hashid.EntityID)
	require.NoError(t, err)
	source, err := f.db.Entity.Get(context.Background(), sourceID)
	require.NoError(t, err)
	backend, err := url.Parse(f.policies[0].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	var refuse atomic.Bool
	refuse.Store(true)
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, source.Source) {
			deletes.Add(1)
			if refuse.Load() {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>controlled old-source cleanup failure</Message></Error>")
				return
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetServer(server.URL).Save(context.Background())
	require.NoError(t, err)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	f.recycling = true
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	require.Eventually(t, func() bool { return deletes.Load() > 0 }, 30*time.Second, 50*time.Millisecond)
	require.Equal(t, payload, f.readFile(t, uri))
	f.assertObjectCounts(t, 2, 1)
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	item, err := f.db.RelocationItem.Query().Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, relocationitem.SourceCleanupPending, item.SourceCleanup)
	w.stop(t)
	refuse.Store(false)
	w = launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	require.Eventually(t, func() bool {
		current, err := f.db.RelocationItem.Get(context.Background(), item.ID)
		return err == nil && current.SourceCleanup == relocationitem.SourceCleanupCleaned
	}, 40*time.Second, 50*time.Millisecond)
	f.assertObjectCounts(t, 1, 1)
	require.Equal(t, payload, f.readFile(t, uri))
	f.waitForStorageTask(t, accepted.ID, "completed")
}

func TestStorageRelocationCleanupRetainsUnselectedSharedSources(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	memberToken := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["settings"] = map[string]any{"max_walked_files": 10000}
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = memberToken
	uri := "cloudreve://my/shared-source.txt"
	payload := []byte("the unselected copy retains its original location")
	f.upload(t, uri, payload, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/copy", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{uri}, "dst": "cloudreve://my/copy", "copy": true}, nil)
	copyURI := "cloudreve://my/copy/shared-source.txt"
	beforeCopy := f.fileInfo(t, copyURI)
	var before fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &before)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	f.recycling = true
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	require.Eventually(t, func() bool {
		item, err := f.db.RelocationItem.Query().Only(context.Background())
		return err == nil && item.SourceCleanup == relocationitem.SourceCleanupRetained
	}, 30*time.Second, 50*time.Millisecond)
	f.assertObjectCounts(t, 2, 1)
	require.Equal(t, payload, f.readFile(t, uri))
	require.Equal(t, payload, f.readFile(t, copyURI))
	afterCopy := f.fileInfo(t, copyURI)
	require.Equal(t, beforeCopy.PrimaryEntity, afterCopy.PrimaryEntity)
	require.Equal(t, beforeCopy.ExtendedInfo.Entities, afterCopy.ExtendedInfo.Entities)
	var after fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &after)
	require.Equal(t, before, after)
}

func TestStorageRelocationCleanupRetainsSeparatePhysicalAlias(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri, aliasURI := "cloudreve://my/existing.txt", "cloudreve://my/imported/legacy-object"
	payload := []byte("persisted object before storage extension")
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/imported", "type": "folder"}, nil)
	imported := f.acceptPhysicalImport(t)
	f.recycling = true
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, imported.ID, "completed")
	before, aliasBefore := f.fileInfo(t, uri), f.fileInfo(t, aliasURI)
	require.NotEqual(t, before.PrimaryEntity, aliasBefore.PrimaryEntity)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	f.waitForStorageTask(t, accepted.ID, "completed")
	require.Eventually(t, func() bool {
		item, err := f.db.RelocationItem.Query().Only(context.Background())
		return err == nil && item.SourceCleanup == relocationitem.SourceCleanupRetained
	}, 30*time.Second, 50*time.Millisecond)
	f.assertObjectCounts(t, 1, 1)
	require.Equal(t, payload, f.readFile(t, uri))
	require.Equal(t, payload, f.readFile(t, aliasURI))
	after, aliasAfter := f.fileInfo(t, uri), f.fileInfo(t, aliasURI)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Equal(t, aliasBefore.PrimaryEntity, aliasAfter.PrimaryEntity)
	require.Equal(t, aliasBefore.ExtendedInfo.Entities, aliasAfter.ExtendedInfo.Entities)
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore, capacityAfter)
}
