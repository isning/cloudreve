package controllers_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/storageobjectreader"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageTerminalPlanRecoversWhenExecutionNodeDisappears(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	for _, name := range []string{"first", "second"} {
		f.upload(t, "cloudreve://my/node-review/"+name+".txt", []byte("retained original"), nil)
	}
	var accepted explorer.TaskResponse
	sources := []string{"cloudreve://my/node-review"}
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": sources, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	_, err = relocation.AdvanceSingle(context.Background(), f.dep, id, 2, sources, f.policies[1].ID)
	require.NoError(t, err)
	require.NoError(t, manager.EnsureRelocationCleanup(context.Background(), f.dep, id))
	require.NoError(t, f.db.Node.Update().SetCapabilities(&boolset.BooleanSet{}).Exec(context.Background()))
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "error")
	f.recycling = true
	cleaner := launchStorageWorker(t, f)
	_ = cleaner.ready(t)
	require.Eventually(t, func() bool {
		items, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(id)).All(context.Background())
		if err != nil || len(items) != 2 {
			return false
		}
		for _, item := range items {
			if item.State != relocationitem.StateFailed {
				return false
			}
		}
		return true
	}, 35*time.Second, 50*time.Millisecond, "independent maintenance closes terminal unclaimed plans")
	for _, name := range []string{"first", "second"} {
		require.Equal(t, []byte("retained original"), f.readFile(t, "cloudreve://my/node-review/"+name+".txt"))
	}
}

func TestStorageReadCompletionRecoversAfterSQLFailure(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	capabilities := &boolset.BooleanSet{}
	boolset.Set(types.NodeCapabilityRelocate, true, capabilities)
	require.NoError(t, f.db.Node.Update().SetCapabilities(capabilities).Exec(context.Background()))
	uri := "cloudreve://my/read-completion.txt"
	f.upload(t, uri, []byte("retain until reads have actually finished"), nil)
	var blocked atomic.Bool
	var readerFailures, attemptFailures atomic.Int32
	blocked.Store(true)
	f.db.StorageObjectReader.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if value, ok := mutation.(*ent.StorageObjectReaderMutation).Finished(); ok && value && blocked.Load() {
				readerFailures.Add(1)
				return nil, errors.New("controlled reader completion SQL outage")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	f.db.RelocationAttempt.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if value, ok := mutation.(*ent.RelocationAttemptMutation).SourceReadFinished(); ok && value && blocked.Load() {
				attemptFailures.Add(1)
				return nil, errors.New("controlled attempt completion SQL outage")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	f.dep.IoIntenseQueue(context.Background()).Start()
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	f.waitForStorageTask(t, accepted.ID, "completed")
	require.Greater(t, readerFailures.Load(), int32(0))
	require.Greater(t, attemptFailures.Load(), int32(0))
	unfinished, err := f.db.StorageObjectReader.Query().Where(storageobjectreader.Finished(false)).Count(context.Background())
	require.NoError(t, err)
	require.Greater(t, unfinished, 0)
	f.assertObjectCounts(t, 1, 1)
	blocked.Store(false)
	require.Eventually(t, func() bool {
		readers, err := f.db.StorageObjectReader.Query().Where(storageobjectreader.Finished(false)).Count(context.Background())
		if err != nil || readers != 0 {
			return false
		}
		attempts, err := f.db.RelocationAttempt.Query().Where(relocationattempt.SourceReadFinished(false)).Count(context.Background())
		return err == nil && attempts == 0
	}, 15*time.Second, 50*time.Millisecond, "completed reads retain exact acknowledgement evidence through a temporary SQL outage")
	f.dep.EntityRecycleQueue(context.Background()).Start()
	require.Eventually(t, func() bool {
		items, err := f.db.RelocationItem.Query().All(context.Background())
		return err == nil && len(items) == 1 && items[0].SourceCleanup == relocationitem.SourceCleanupCleaned
	}, 30*time.Second, 50*time.Millisecond)
	f.assertObjectCounts(t, 0, 1)
	require.Equal(t, []byte("retain until reads have actually finished"), f.readFile(t, uri))
}

func TestStorageRelocationPermanentFailureClosesUnclaimedItems(t *testing.T) {
	testStorageRelocationPermanentFailure(t, false)
}

func TestStorageRelocationFailureAcknowledgementStaysRecoverable(t *testing.T) {
	testStorageRelocationPermanentFailure(t, true)
}

func testStorageRelocationPermanentFailure(t *testing.T, failAcknowledgement bool) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	for _, name := range []string{"first", "second", "third"} {
		f.upload(t, "cloudreve://my/terminal-review/"+name+".txt", []byte("original bytes"), nil)
	}
	backend, err := url.Parse(f.policies[1].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.Method == http.MethodGet && strings.Contains(response.Request.URL.Path, "/.cloudreve-relocation/") {
			response.Body.Close()
			body := strings.Repeat("X", int(response.ContentLength))
			response.Body = io.NopCloser(strings.NewReader(body))
		}
		return nil
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Exec(context.Background()))
	require.NoError(t, f.dep.KV().Delete(inventory.StoragePolicyCacheKey, "2"))
	var blocked atomic.Bool
	var rejected atomic.Int32
	blocked.Store(failAcknowledgement)
	t.Cleanup(func() { blocked.Store(false) })
	if failAcknowledgement {
		f.db.RelocationItem.Use(func(next ent.Mutator) ent.Mutator {
			return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
				if state, ok := mutation.(*ent.RelocationItemMutation).State(); ok && state == relocationitem.StateFailed && blocked.Load() {
					rejected.Add(1)
					return nil, errors.New("controlled failure acknowledgement SQL outage")
				}
				return next.Mutate(ctx, mutation)
			})
		})
		f.dep.IoIntenseQueue(context.Background()).Start()
	}
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/terminal-review"}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	if failAcknowledgement {
		require.Eventually(t, func() bool { return rejected.Load() > 0 }, 70*time.Second, 50*time.Millisecond)
		require.Eventually(t, func() bool {
			job, err := f.db.Task.Get(context.Background(), id)
			return err == nil && job.Status == task.StatusSuspending
		}, 5*time.Second, 50*time.Millisecond, "unacknowledged failure cannot terminalize the main task")
		blocked.Store(false)
		require.NoError(t, f.db.RelocationItem.Update().Where(relocationitem.TaskID(id)).SetLeaseUntil(time.Now().Add(-time.Second)).Exec(context.Background()))
	} else {
		worker := launchStorageWorkerWithWorkflows(t, f)
		f.remote = worker.ready(t)
		f.login(t)
	}
	f.waitForStorageTask(t, accepted.ID, "error")
	items, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(id)).All(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 3)
	for _, item := range items {
		require.Equal(t, relocationitem.StateFailed, item.State, "terminal task cannot strand unclaimed work")
	}
	for _, name := range []string{"first", "second", "third"} {
		require.Equal(t, []byte("original bytes"), f.readFile(t, "cloudreve://my/terminal-review/"+name+".txt"))
	}
}
