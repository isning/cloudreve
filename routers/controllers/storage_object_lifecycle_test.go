package controllers_test

import (
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/storageobjectreader"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) acceptPhysicalImport(t *testing.T) explorer.TaskResponse {
	t.Helper()
	token := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var job explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/import", map[string]any{"src": "/", "dst": "/imported", "user_id": hashid.EncodeUserID(f.dep.HashIDEncoder(), 2), "policy_id": f.policies[0].ID, "recursive": true}, &job)
	f.token = token
	return job
}

func TestStorageNativeRecycleProtectsPhysicalImportAliases(t *testing.T) {
	for _, crossPolicy := range []bool{false, true} {
		t.Run(map[bool]string{false: "same_policy", true: "different_policy"}[crossPolicy], func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			if crossPolicy {
				original := f.policies[0]
				settings := *original.Settings
				settings.Region = "us-west-2"
				alias, err := f.db.StoragePolicy.Create().SetName("Alias of the same physical bucket").SetType(original.Type).SetServer(original.Server + "/").SetBucketName(original.BucketName).SetAccessKey(original.AccessKey).SetSecretKey(original.SecretKey).SetIsPrivate(true).SetFileNameRule(original.FileNameRule).SetDirNameRule(original.DirNameRule).SetSettings(&settings).Save(context.Background())
				require.NoError(t, err)
				f.policies[0] = alias
			}
			_, err := f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String("empty-object"), Body: bytes.NewReader(nil)})
			require.NoError(t, err)
			// Administrator imports from A although the target account only has B.
			f.assignPolicies(t, f.policies[1].ID)
			folder := "cloudreve://my/imported"
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
			before := f.fileInfo(t, "cloudreve://my/existing.txt")
			job := f.acceptPhysicalImport(t)
			f.recycling = true
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			completed := f.waitForStorageTask(t, job.ID, "completed")
			require.Zero(t, completed.Summary.Props["failed"], "native physical import must succeed before alias protection is exercised")
			imported := folder + "/legacy-object"
			info := f.fileInfo(t, imported)
			require.NotEqual(t, before.PrimaryEntity, info.PrimaryEntity)
			empty := f.fileInfo(t, folder+"/empty-object")
			require.Zero(t, empty.Size)
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), empty.ExtendedInfo.Entities[0].StoragePolicy.ID)
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), info.ExtendedInfo.Entities[0].StoragePolicy.ID)
			require.Equal(t, []byte("persisted object before storage extension"), f.readFile(t, imported))
			f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/existing.txt"}, "skip_soft_delete": true}, nil)
			require.Eventually(t, func() bool {
				n, err := f.db.Task.Query().Where(task.Type(queue.ExplicitEntityRecycleTaskType), task.StatusEQ(task.StatusCompleted)).Count(context.Background())
				return err == nil && n > 0
			}, 30*time.Second, 50*time.Millisecond)
			f.assertObjectCounts(t, 2, 0)
			require.Equal(t, []byte("persisted object before storage extension"), f.readFile(t, imported))
			// The privileged import path never becomes an ordinary member write bypass.
			require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/import", map[string]any{"src": "/", "dst": "/forbidden", "user_id": hashid.EncodeUserID(f.dep.HashIDEncoder(), 2), "policy_id": f.policies[0].ID}))

		})
	}
}

func TestStorageStalePhysicalListingCannotCreateDeletedAlias(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/imported", "type": "folder"}, nil)
	backend, err := url.Parse(f.policies[0].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	listed, deleted := make(chan struct{}), make(chan struct{})
	allowList, allowDelete := make(chan struct{}), make(chan struct{})
	var listOnce, deleteOnce, releaseList, releaseDelete sync.Once
	unblock := func() { releaseList.Do(func() { close(allowList) }); releaseDelete.Do(func() { close(allowDelete) }) }
	defer unblock()
	proxy.ModifyResponse = func(res *http.Response) error {
		if res.Request.Method == http.MethodGet && !strings.HasSuffix(res.Request.URL.Path, "/legacy-object") && res.StatusCode == http.StatusOK {
			listOnce.Do(func() {
				close(listed)
				select {
				case <-allowList:
				case <-res.Request.Context().Done():
				}
			})
		}
		return nil
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/legacy-object") {
			deleteOnce.Do(func() {
				close(deleted)
				select {
				case <-allowDelete:
				case <-r.Context().Done():
				}
			})
		}
		proxy.ServeHTTP(w, r)
	}))
	defer func() { unblock(); server.Close() }()
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetServer(server.URL).Save(context.Background())
	require.NoError(t, err)
	job := f.acceptPhysicalImport(t)
	importer := launchStorageWorkerWithWorkflows(t, f)
	_ = importer.ready(t)
	select {
	case <-listed:
	case <-time.After(40 * time.Second):
		t.Fatal("real import did not receive physical listing")
	}
	// Separate API dependency graph has no recycle worker, so the HTTP delete
	// publishes the native task before the provider boundary is paused.
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/existing.txt"}, "skip_soft_delete": true}, nil)
	f.recycling = true
	recycler := launchStorageWorker(t, f)
	_ = recycler.ready(t)
	select {
	case <-deleted:
	case <-time.After(40 * time.Second):
		t.Fatal("native recycler did not reach physical Delete")
	}
	releaseList.Do(func() { close(allowList) })
	// Deletion owns the location gate. The stale list is allowed to resume;
	// admission must reopen after deletion instead of trusting that list.
	releaseDelete.Do(func() { close(allowDelete) })
	f.remote = importer.ready(t)
	f.login(t)
	result := f.waitForStorageTask(t, job.ID, "completed")
	require.EqualValues(t, 1, result.Summary.Props["failed"])
	require.Eventually(t, func() bool {
		n, err := f.db.Entity.Query().Where(entity.Source("legacy-object")).Count(context.Background())
		return err == nil && n == 0
	}, 30*time.Second, 50*time.Millisecond)
	count, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("legacy-object")).Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, count)
	f.assertObjectCounts(t, 0, 0)
}

func TestStorageNativeRecycleWaitsForActiveMigrationRead(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	backend, err := url.Parse(f.policies[0].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	reading, release := make(chan struct{}), make(chan struct{})
	var pauseOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/legacy-object") {
			pauseOnce.Do(func() {
				close(reading)
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})
		}
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer func() { unblock(); server.Close() }()
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetServer(server.URL).Save(context.Background())
	require.NoError(t, err)
	var job explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/existing.txt"}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &job)
	ioWorker := launchStorageWorkerWithWorkflows(t, f)
	_ = ioWorker.ready(t)
	select {
	case <-reading:
	case <-time.After(45 * time.Second):
		t.Fatal("migration did not open real source read")
	}
	readers, err := f.db.StorageObjectReader.Query().Where(storageobjectreader.Finished(false)).Count(context.Background())
	require.NoError(t, err)
	require.Positive(t, readers)
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/existing.txt"}, "skip_soft_delete": true}, nil)
	f.recycling = true
	recycler := launchStorageWorker(t, f)
	_ = recycler.ready(t)
	require.Eventually(t, func() bool {
		n, err := f.db.Task.Query().Where(task.Type(queue.ExplicitEntityRecycleTaskType), task.StatusEQ(task.StatusCompleted)).Count(context.Background())
		return err == nil && n > 0
	}, 30*time.Second, 50*time.Millisecond)
	require.Zero(t, deletes.Load())
	f.assertObjectCounts(t, 1, 0)
	unblock()
	f.remote = ioWorker.ready(t)
	f.login(t)
	f.waitForStorageTask(t, job.ID, "error")
	count, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("existing.txt")).Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, count)
	require.Eventually(t, func() bool {
		n, err := f.db.StorageObjectReader.Query().Where(storageobjectreader.Finished(false)).Count(context.Background())
		return err == nil && n == 0
	}, 10*time.Second, 50*time.Millisecond)
}
