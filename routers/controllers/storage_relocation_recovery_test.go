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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) waitForRelocationItem(t *testing.T, id string, state relocationitem.State) *ent.RelocationItem {
	t.Helper()
	jobID, err := f.dep.HashIDEncoder().Decode(id, hashid.TaskID)
	require.NoError(t, err)
	var found *ent.RelocationItem
	deadline := time.Now().Add(50 * time.Second)
	for time.Now().Before(deadline) {
		found, err = f.db.RelocationItem.Query().Where(relocationitem.TaskID(jobID)).Only(context.Background())
		if err == nil && found.State == state {
			return found
		}
		if err == nil && found.State == relocationitem.StateFailed {
			t.Fatal("migration journal reached unexpected failure")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("migration journal did not reach requested durable boundary")
	return nil
}

func TestStorageRelocationRestartsAtPlanAndVerifiedBoundaries(t *testing.T) {
	for _, boundary := range []relocationitem.State{relocationitem.StatePlanned, relocationitem.StateVerified} {
		t.Run(string(boundary), func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			uri := "cloudreve://my/restart.txt"
			data := []byte("durable boundary recovery preserves identity and usage")
			f.upload(t, uri, data, nil)
			before := f.fileInfo(t, uri)
			var capacityBefore fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			_ = w.ready(t)
			item := f.waitForRelocationItem(t, accepted.ID, boundary)
			w.stop(t)
			require.True(t, bytes.Equal(data, f.readFile(t, uri)), "source remains readable before the reference commit")
			if boundary == relocationitem.StateVerified {
				f.assertObjectCounts(t, 2, 1)
			} else {
				f.assertObjectCounts(t, 2, 0)
			}
			restarted := launchStorageWorkerWithWorkflows(t, f)
			f.remote = restarted.ready(t)
			f.login(t)
			f.waitForStorageTask(t, accepted.ID, "completed")
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.ExtendedInfo.Entities[0].ID, after.ExtendedInfo.Entities[0].ID)
			require.Len(t, after.ExtendedInfo.Entities, 1)
			require.True(t, bytes.Equal(data, f.readFile(t, uri)))
			var capacityAfter fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
			require.Equal(t, capacityBefore.Used, capacityAfter.Used)
			attempts, err := f.db.RelocationAttempt.Query().Where(relocationattempt.ItemID(item.ID)).Count(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, attempts, "verified target is reused rather than uploaded twice")
			f.assertObjectCounts(t, 2, 1)
		})
	}
}

func TestStorageRelocationInterruptedPutRetainsUnknownOwnedAttempt(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/interrupted.txt"
	data := []byte("provider can finish after the original worker exits")
	f.upload(t, uri, data, nil)
	before := f.fileInfo(t, uri)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	backend, err := url.Parse(f.policies[1].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var startOnce, releaseOnce, finishOnce sync.Once
	var completionStatus atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "owned provider read failed", 500)
				return
			}
			startOnce.Do(func() { close(started) })
			<-release
			// The controlled provider has received the bytes and deliberately
			// completes a real S3 PUT after its original client disappears.
			providerCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r = r.Clone(providerCtx)
			r.Body = io.NopCloser(bytes.NewReader(body))
			receipt := httptest.NewRecorder()
			proxy.ServeHTTP(receipt, r)
			completionStatus.Store(int32(receipt.Code))
			finishOnce.Do(func() { close(finished) })
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); server.Close() })
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Save(context.Background())
	require.NoError(t, err)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	_ = w.ready(t)
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("controlled provider PUT did not start")
	}
	w.stop(t)
	attempt, err := f.db.RelocationAttempt.Query().Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, relocationattempt.IoStateUnknown, attempt.IoState)
	require.True(t, attempt.SourceReadFinished, "local source read ends independently of unknown remote writes")
	require.Equal(t, relocationattempt.CleanupPending, attempt.Cleanup)
	require.NotEmpty(t, attempt.TargetKey)
	require.True(t, bytes.Equal(data, f.readFile(t, uri)))
	releaseOnce.Do(func() { close(release) })
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("late provider write did not finish")
	}
	require.EqualValues(t, http.StatusOK, completionStatus.Load())
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "error")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.ExtendedInfo.Entities[0].ID, after.ExtendedInfo.Entities[0].ID)
	require.Len(t, after.ExtendedInfo.Entities, 1)
	require.True(t, bytes.Equal(data, f.readFile(t, uri)))
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	attemptAfter, err := f.db.RelocationAttempt.Get(context.Background(), attempt.ID)
	require.NoError(t, err)
	require.Equal(t, attempt.TargetKey, attemptAfter.TargetKey)
	require.Equal(t, relocationattempt.IoStateUnknown, attemptAfter.IoState)
	f.assertObjectCounts(t, 2, 1)
}

func TestStorageRelocationRecoversCommittedJournalBeforeTaskProgress(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/committed-restart.txt"
	data := []byte("committed journal wins over old task command and status")
	f.upload(t, uri, data, nil)
	before := f.fileInfo(t, uri)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	_, err := f.db.ExecContext(context.Background(), "CREATE TRIGGER owned_relocation_progress_fail BEFORE UPDATE OF status ON tasks WHEN NEW.type = 'relocate' AND NEW.status = 'completed' BEGIN SELECT RAISE(FAIL, 'owned progress interruption'); END")
	require.NoError(t, err)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	_ = w.ready(t)
	item := f.waitForRelocationItem(t, accepted.ID, relocationitem.StateCommitted)
	w.stop(t)
	oldTask, err := f.db.Task.Get(context.Background(), item.TaskID)
	require.NoError(t, err)
	require.NotEqual(t, task.StatusCompleted, oldTask.Status, "actual database fault must interrupt progress persistence")
	_, err = f.db.ExecContext(context.Background(), "DROP TRIGGER owned_relocation_progress_fail")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		restarted := launchStorageWorkerWithWorkflows(t, f)
		f.remote = restarted.ready(t)
		f.login(t)
		f.waitForStorageTask(t, accepted.ID, "completed")
		after := f.fileInfo(t, uri)
		require.Equal(t, before.ID, after.ID)
		require.Equal(t, before.ExtendedInfo.Entities[0].ID, after.ExtendedInfo.Entities[0].ID)
		require.Len(t, after.ExtendedInfo.Entities, 1)
		require.True(t, bytes.Equal(data, f.readFile(t, uri)))
		var capacityAfter fs.Capacity
		f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
		require.Equal(t, capacityBefore.Used, capacityAfter.Used)
		f.assertObjectCounts(t, 2, 1)
		restarted.stop(t)
	}
}

func TestStorageRelocationRechecksMissingOrInvalidVerification(t *testing.T) {
	for _, fault := range []string{"missing", "incorrect_digest", "corrupt_target"} {
		t.Run(fault, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			uri := "cloudreve://my/reverify.txt"
			data := []byte("recovery must not trust object existence or a broken record")
			f.upload(t, uri, data, nil)
			before := f.fileInfo(t, uri)
			f.fillMigrationQuota(t)
			capacitiesBefore := f.migrationCapacities(t)
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			_ = w.ready(t)
			item := f.waitForRelocationItem(t, accepted.ID, relocationitem.StateVerified)
			w.stop(t)
			attempt, err := f.db.RelocationAttempt.Get(context.Background(), item.ActiveAttemptID)
			require.NoError(t, err)
			switch fault {
			case "missing":
				_, err = f.db.RelocationAttempt.UpdateOne(attempt).SetVerified(false).SetVerifiedSize(0).SetVerifiedDigest("").Save(context.Background())
			case "incorrect_digest":
				_, err = f.db.RelocationAttempt.UpdateOne(attempt).SetVerifiedDigest(strings.Repeat("0", 64)).Save(context.Background())
			case "corrupt_target":
				bad := append([]byte(nil), data...)
				bad[len(bad)-1] ^= 0xff
				_, err = f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(attempt.TargetKey), Body: bytes.NewReader(bad)})
			}
			require.NoError(t, err)
			restarted := launchStorageWorkerWithWorkflows(t, f)
			f.remote = restarted.ready(t)
			f.login(t)
			f.waitForStorageTask(t, accepted.ID, "completed")
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.ExtendedInfo.Entities[0].ID, after.ExtendedInfo.Entities[0].ID)
			require.Len(t, after.ExtendedInfo.Entities, 1)
			require.True(t, bytes.Equal(data, f.readFile(t, uri)))
			require.Equal(t, capacitiesBefore, f.migrationCapacities(t))
			// Redeliver the completed command twice. Durable references and
			// accounting must not be applied again on either recovery.
			for i := 0; i < 2; i++ {
				restarted.stop(t)
				jobID, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
				require.NoError(t, err)
				require.NoError(t, f.db.Task.UpdateOneID(jobID).SetStatus(task.StatusProcessing).Exec(context.Background()))
				restarted = launchStorageWorkerWithWorkflows(t, f)
				f.remote = restarted.ready(t)
				f.login(t)
				report := f.waitForStorageTask(t, accepted.ID, "completed")
				require.Equal(t, float64(len(data)), report.Summary.Props["bytes_copied"])
				require.Equal(t, capacitiesBefore, f.migrationCapacities(t))
				require.Len(t, f.fileInfo(t, uri).ExtendedInfo.Entities, 1)
			}
			if fault == "corrupt_target" {
				f.assertObjectCounts(t, 2, 2)
			} else {
				f.assertObjectCounts(t, 2, 1)
			}
		})
	}
}
