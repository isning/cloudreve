package controllers_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) rejectMigrationLocatorChanges(t *testing.T) {
	t.Helper()
	for _, id := range []int{f.policies[0].ID, f.policies[1].ID} {
		endpoint := fmt.Sprintf("/api/v4/admin/policy/%d", id)
		var original ent.StoragePolicy
		f.request(t, http.MethodGet, endpoint, nil, &original)
		next := original
		next.Server = "http://127.0.0.1:1"
		require.NotZero(t, f.responseCode(t, http.MethodPut, endpoint, map[string]any{"policy": next}))
		var after ent.StoragePolicy
		f.request(t, http.MethodGet, endpoint, nil, &after)
		require.Equal(t, original.Server, after.Server)
		next = original
		next.Name += " renamed"
		next.SecretKey = storageRandom(t)
		f.request(t, http.MethodPut, endpoint, map[string]any{"policy": next}, nil)
		f.request(t, http.MethodPut, endpoint, map[string]any{"policy": original}, nil)
	}
}

func TestStoragePlannedRelocationProtectsUnallocatedTargetWithoutEntities(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	f.upload(t, "cloudreve://my/protected.txt", []byte("pending migration dependency"), nil)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/protected.txt"}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	jobID, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	_ = w.ready(t)
	require.Eventually(t, func() bool {
		item, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(jobID)).Only(context.Background())
		return err == nil && item.State == relocationitem.StatePlanned
	}, 10*time.Second, 20*time.Millisecond)
	// The issuing master's API can revoke the grant while the independent
	// worker is between durable plan and transfer iterations.
	f.assignPolicies(t, f.policies[0].ID)
	admin := launchStorageWorker(t, f)
	f.remote = admin.ready(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID), nil))
	f.rejectMigrationLocatorChanges(t)
	// A never-used, never-granted policy remains deletable.
	p := f.policies[1]
	free, err := f.db.StoragePolicy.Create().SetName("Unused owned policy").SetType(p.Type).SetServer(p.Server).SetBucketName("unused-owned-bucket").SetSettings(p.Settings).Save(context.Background())
	require.NoError(t, err)
	f.request(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", free.ID), nil, nil)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "error")
	f.assertObjectCounts(t, 2, 0)
	// Terminal task status does not erase the unresolved journal dependency.
	f.remote = admin.ready(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.rejectMigrationLocatorChanges(t)
}

func TestStorageCommittedRelocationKeepsResidualLocationDependencies(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	f.upload(t, "cloudreve://my/committed.txt", []byte("committed target still has source cleanup pending"), nil)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/committed.txt"}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.rejectMigrationLocatorChanges(t)
}
