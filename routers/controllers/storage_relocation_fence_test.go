package controllers_test

import (
	"bytes"
	"context"
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
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationExpiredWorkerCannotOverwriteWinningCommit(t *testing.T) {
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
	// A controlled clock boundary expires the journal lease while every old
	// worker goroutine is paused. Only the owned child process is signaled.
	require.NoError(t, f.db.RelocationItem.UpdateOneID(item.ID).SetLeaseUntil(time.Now().Add(-time.Second)).Exec(context.Background()))
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
	require.NoError(t, old.cmd.Process.Signal(syscall.SIGCONT))
	require.Eventually(t, func() bool {
		attempt, err := f.db.RelocationAttempt.Get(context.Background(), oldAttempt.ID)
		return err == nil && attempt.SourceReadFinished && attempt.IoState == relocationattempt.IoStateUnknown
	}, 20*time.Second, 20*time.Millisecond, "stale client must cancel and retain its own unknown I/O")
	old.stop(t)
	// The provider completes its old object after both takeover and old client
	// termination. Existence/deletion cannot settle this unknown ownership fact.
	releaseOnce.Do(func() { close(release) })
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("controlled late provider did not finish")
	}
	require.Equal(t, int32(http.StatusOK), lateStatus.Load())
	f.waitForStorageTask(t, accepted.ID, "completed")
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
	f.assertObjectCounts(t, 2, 2)
}
