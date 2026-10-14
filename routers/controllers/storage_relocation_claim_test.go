package controllers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationTwoWorkersCommitOnlyOnce(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/claim.txt"
	data := []byte("only the current durable claim may commit this entity")
	f.upload(t, uri, data, nil)
	before := f.fileInfo(t, uri)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	first := launchStorageWorkerWithWorkflows(t, f)
	second := launchStorageWorkerWithWorkflows(t, f)
	for _, w := range []*storageWorker{first, second} {
		_ = w.ready(t)
	}
	f.remote = first.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	first.stop(t)
	second.stop(t)
	jobID, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	item, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(jobID)).Only(context.Background())
	require.NoError(t, err)
	require.Equal(t, relocationitem.StateCommitted, item.State)
	count, err := item.QueryAttempts().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, count)
	// Deliberately redeliver the same persisted task model. The journal fact
	// must win over an old processing status without a second reference swap.
	require.NoError(t, f.db.Task.UpdateOneID(jobID).SetStatus(task.StatusProcessing).Exec(context.Background()))
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Len(t, after.ExtendedInfo.Entities, 1)
	require.Equal(t, data, f.readFile(t, uri))
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	f.assertObjectCounts(t, 2, 1)
}
