package controllers_test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationExpiredWorkerCannotOverwriteWinningCommit(t *testing.T) {
	testExpiredRelocationWorker(t, false, false)
}

func TestStorageRelocationCompensationFindsLatePut(t *testing.T) {
	testExpiredRelocationWorker(t, true, false)
}

func TestStorageRelocationLateCompensationSurvivesDeletedHistory(t *testing.T) {
	testExpiredRelocationWorker(t, true, true)
}

func testExpiredRelocationWorker(t *testing.T, compensate, deleteHistory bool) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/fenced.txt"
	data := []byte("late old write must not replace the winner")
	f.upload(t, uri, data, nil)
	before := f.fileInfo(t, uri)
	backend, err := url.Parse(f.policies[1].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	started, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var puts atomic.Int32
	var lateStatus atomic.Int32
	var oldKey atomic.Value
	oldKey.Store("")
	var oldDeletes atomic.Int32
	var lateObjectObserved atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") && puts.Add(1) == 1 {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "controlled body failure", 500)
				return
			}
			close(started)
			<-release
			providerCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r = r.Clone(providerCtx)
			r.Body = io.NopCloser(bytes.NewReader(body))
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, r)
			lateStatus.Store(int32(recorder.Code))
			close(ended)
			return
		}
		if r.Method == http.MethodDelete && oldKey.Load().(string) != "" && strings.HasSuffix(r.URL.Path, oldKey.Load().(string)) {
			oldDeletes.Add(1)
			if lateStatus.Load() == int32(http.StatusOK) {
				meta, err := f.s3.HeadObject(&s3.HeadObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(oldKey.Load().(string))})
				if err == nil && aws.Int64Value(meta.ContentLength) == int64(len(data)) {
					lateObjectObserved.Store(true)
				}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); server.Close() })
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Exec(context.Background()))
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	old := launchStorageWorkerWithWorkflows(t, f)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); _ = old.cmd.Process.Signal(syscall.SIGCONT) })
	_ = old.ready(t)
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("controlled old PUT did not start")
	}
	require.NoError(t, old.cmd.Process.Signal(syscall.SIGSTOP))
	item := f.waitForRelocationItem(t, accepted.ID, relocationitem.StateCopying)
	oldAttempt, err := f.db.RelocationAttempt.Get(context.Background(), item.ActiveAttemptID)
	require.NoError(t, err)
	oldKey.Store(oldAttempt.TargetKey)
	// A controlled clock boundary expires the journal lease while every old
	// worker goroutine is paused. Only the owned child process is signaled.
	require.NoError(t, f.db.RelocationItem.UpdateOneID(item.ID).SetLeaseUntil(time.Now().Add(-time.Second)).Exec(context.Background()))
	f.recycling = compensate
	winner := launchStorageWorkerWithWorkflows(t, f)
	f.remote = winner.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	committed, err := f.db.RelocationItem.Get(context.Background(), item.ID)
	require.NoError(t, err)
	require.Greater(t, committed.Fence, item.Fence)
	newAttempt, err := f.db.RelocationAttempt.Get(context.Background(), committed.ActiveAttemptID)
	require.NoError(t, err)
	require.NotEqual(t, oldAttempt.TargetKey, newAttempt.TargetKey)
	if deleteHistory {
		f.loginAs(t, "storage-admin@example.com", f.adminPassword)
		f.request(t, http.MethodPost, "/api/v4/admin/queue/batch/delete", map[string]any{"ids": []int{item.TaskID}}, nil)
		exists, err := f.db.Task.Query().Where(task.ID(item.TaskID)).Exist(context.Background())
		require.NoError(t, err)
		require.False(t, exists)
		winner.stop(t)
		winner = launchStorageWorker(t, f)
		f.remote = winner.ready(t)
		f.login(t)
	}
	if compensate {
		require.Eventually(t, func() bool { return oldDeletes.Load() > 0 }, 30*time.Second, 50*time.Millisecond)
		protected, err := f.db.RelocationItem.Get(context.Background(), item.ID)
		require.NoError(t, err)
		require.Equal(t, relocationitem.SourceCleanupPending, protected.SourceCleanup)
		f.assertObjectCounts(t, 2, 1)
	}
	require.NoError(t, old.cmd.Process.Signal(syscall.SIGCONT))
	require.Eventually(t, func() bool {
		attempt, err := f.db.RelocationAttempt.Get(context.Background(), oldAttempt.ID)
		return err == nil && attempt.SourceReadFinished && attempt.IoState == relocationattempt.IoStateUnknown
	}, 20*time.Second, 20*time.Millisecond, "stale client must cancel and retain its own unknown I/O")
	old.stop(t)
	if compensate {
		require.Eventually(t, func() bool { return oldDeletes.Load() > 0 }, 30*time.Second, 50*time.Millisecond, "first compensation must precede late provider completion")
		basis, err := f.db.RelocationAttempt.Get(context.Background(), oldAttempt.ID)
		require.NoError(t, err)
		require.Equal(t, relocationattempt.IoStateUnknown, basis.IoState)
		require.Equal(t, relocationattempt.CleanupPending, basis.Cleanup)
	}
	// The provider completes its old object after both takeover and old client
	// termination. Existence/deletion cannot settle this unknown ownership fact.
	releaseOnce.Do(func() { close(release) })
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("controlled late provider did not finish")
	}
	require.Equal(t, int32(http.StatusOK), lateStatus.Load())
	if !deleteHistory {
		f.waitForStorageTask(t, accepted.ID, "completed")
	}
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Equal(t, data, f.readFile(t, uri))
	current, err := f.db.Entity.Get(context.Background(), committed.TargetEntityID)
	require.NoError(t, err)
	require.Equal(t, newAttempt.TargetKey, current.Source)
	oldAttempt, err = f.db.RelocationAttempt.Get(context.Background(), oldAttempt.ID)
	require.NoError(t, err)
	require.Equal(t, relocationattempt.IoStateUnknown, oldAttempt.IoState)
	require.Equal(t, relocationattempt.CleanupPending, oldAttempt.Cleanup)
	newAttempt, err = f.db.RelocationAttempt.Get(context.Background(), newAttempt.ID)
	require.NoError(t, err)
	require.Equal(t, relocationattempt.CleanupRetained, newAttempt.Cleanup)
	if !compensate {
		f.assertObjectCounts(t, 2, 2)
		return
	}
	require.Eventually(t, func() bool { return lateObjectObserved.Load() }, 35*time.Second, 50*time.Millisecond, "independent maintenance must rediscover the real late object")
	require.Eventually(t, func() bool {
		_, err := f.s3.HeadObject(&s3.HeadObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(oldAttempt.TargetKey)})
		return err != nil
	}, 10*time.Second, 50*time.Millisecond)
	basis, err := f.db.RelocationAttempt.Get(context.Background(), oldAttempt.ID)
	require.NoError(t, err)
	require.Equal(t, relocationattempt.IoStateUnknown, basis.IoState)
	require.Equal(t, relocationattempt.CleanupPending, basis.Cleanup)
	f.assertObjectCounts(t, 1, 1)
	require.Equal(t, data, f.readFile(t, uri))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.rejectMigrationLocatorChanges(t)
	for _, policy := range f.policies {
		require.NotZero(t, f.responseCode(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", policy.ID), nil))
	}
}
