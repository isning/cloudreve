package controllers_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) enableMigration(t *testing.T, enabled bool) {
	t.Helper()
	token := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	bs, err := boolset.FromString(group["permissions"].(string))
	require.NoError(t, err)
	boolset.Set(10, enabled, bs)
	group["permissions"] = bs
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = token
}

func (f *storageFixture) waitForStorageTask(t *testing.T, id string, status string) explorer.TaskResponse {
	t.Helper()
	var found explorer.TaskResponse
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var list explorer.TaskListResponse
		f.request(t, http.MethodGet, "/api/v4/workflow?category=general&page_size=100", nil, &list)
		for _, job := range list.Tasks {
			if job.ID == id {
				found = job
				if job.Status == status {
					return found
				}
				if job.Status == "completed" || job.Status == "error" || job.Status == "canceled" {
					t.Fatalf("storage task reached unexpected terminal state %s; expected %s", job.Status, status)
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("persisted storage task did not reach expected %s state (last observed %s)", status, found.Status)
	return found
}

func TestStorageSamePolicyRelocationPersistsAndCompletesAfterWorkerRestart(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	uri := "cloudreve://my/noop.txt"
	data := []byte("same-policy relocate uses native durable task without changing content")
	f.upload(t, uri, data, nil)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	before := f.fileInfo(t, uri)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	input := map[string]any{"src": []string{uri}, "dst_policy_id": a}
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", input), "allocation alone does not grant migration")
	f.enableMigration(t, true)
	before = f.fileInfo(t, uri)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", input, &accepted)
	require.NotEmpty(t, accepted.ID)
	require.Equal(t, "relocate", accepted.Type)
	require.Equal(t, "queued", accepted.Status)
	f.waitForStorageTask(t, accepted.ID, "queued")
	// The issuing process has not started its native I/O worker. Another process
	// must discover the persisted task, execute it, and expose the final result.
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	completed := f.waitForStorageTask(t, accepted.ID, "completed")
	require.Equal(t, "relocate", completed.Type)
	require.Equal(t, a, completed.Summary.Props["dst_policy_id"])
	require.Equal(t, []any{uri}, completed.Summary.Props["src_multiple"])
	require.NotNil(t, completed.Node)
	require.True(t, completed.Node.Capabilities.Enabled(4))
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.ExtendedInfo.Entities, after.ExtendedInfo.Entities)
	require.Equal(t, data, f.readFile(t, uri))
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}))
	worker.stop(t)
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	require.Equal(t, data, f.readFile(t, uri))
}

func TestStorageMigrationPermissionIsIndependentOfAllocatedPolicies(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	uri := "cloudreve://my/permission.txt"
	f.upload(t, uri, []byte("allocation still permits ordinary uploads"), nil)
	input := map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)}
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", input))
	f.enableMigration(t, true)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", input, &accepted)
	require.Equal(t, "relocate", accepted.Type)
	f.enableMigration(t, false)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", input))
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), policies[0].ID)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), policies[1].ID)
	f.upload(t, "cloudreve://my/permission-disabled-upload.txt", []byte("migration disable does not disable upload"), policies[1].ID)
}
