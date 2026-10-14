package controllers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationplan"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationDeduplicatesOverlappingTreeAndRootSelections(t *testing.T) {
	for _, root := range []bool{false, true} {
		t.Run(map[bool]string{false: "overlapping", true: "personal_root"}[root], func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			token := f.token
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			group := f.groupDetail(t)
			group["settings"] = map[string]any{"max_walked_files": 10000}
			f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
			f.token = token
			folder, src, outside := "cloudreve://my/tree", "cloudreve://my/tree/source.txt", "cloudreve://my/outside.txt"
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder + "/copies", "type": "folder"}, nil)
			f.upload(t, src, []byte("shared selection"), nil)
			f.upload(t, outside, []byte("outside selection"), nil)
			f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{src}, "dst": folder + "/copies", "copy": true}, nil)
			uris := []string{src, folder + "/copies/source.txt", outside}
			models, err := f.db.File.Query().Where(file.OwnerID(2)).All(context.Background())
			require.NoError(t, err)
			original := map[int]*ent.File{}
			for _, model := range models {
				original[model.ID] = model
			}
			b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
			sources := []string{folder, src, folder, outside}
			if root {
				sources = append(sources, "cloudreve://my/")
				uris = append(uris, "cloudreve://my/existing.txt")
			}
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": sources, "dst_policy_id": b}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			f.waitForStorageTask(t, accepted.ID, "completed")
			for _, uri := range uris {
				info := f.fileInfo(t, uri)
				require.Len(t, info.ExtendedInfo.Entities, 1)
				require.Equal(t, b, info.ExtendedInfo.Entities[0].StoragePolicy.ID)
				require.NotEmpty(t, f.readFile(t, uri))
			}
			models, err = f.db.File.Query().Where(file.OwnerID(2)).All(context.Background())
			require.NoError(t, err)
			for _, model := range models {
				require.Equal(t, original[model.ID].PrimaryEntity, model.PrimaryEntity)
				require.Equal(t, original[model.ID].StoragePolicyFiles, model.StoragePolicyFiles)
				require.Equal(t, original[model.ID].UpdatedAt, model.UpdatedAt)
			}
			items, err := f.db.RelocationItem.Query().All(context.Background())
			require.NoError(t, err)
			expected := 2
			if root {
				expected = 3
			}
			require.Len(t, items, expected)
			refs := 0
			for _, item := range items {
				require.Equal(t, relocationitem.StateCommitted, item.State)
				refs += len(item.References)
			}
			require.Equal(t, expected+1, refs)
			attempts, err := f.db.RelocationAttempt.Query().Count(context.Background())
			require.NoError(t, err)
			require.Equal(t, expected, attempts)
			f.assertObjectCounts(t, 3, expected)
			require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/", "policy_id": b}))
		})
	}
}

func TestStorageRelocationTreePlanningFailsBeforeAnyTransfer(t *testing.T) {
	for _, kind := range []string{"incomplete", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			folder := "cloudreve://my/planning"
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
			f.upload(t, folder+"/good.txt", []byte("first entity must not transfer"), nil)
			if kind == "incomplete" {
				var upload explorer.UploadSessionResponse
				f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": folder + "/pending.txt", "size": 17}, &upload)
			} else {
				f.upload(t, folder+"/unknown.txt", []byte("unsupported entity"), nil)
				model, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("unknown.txt")).Only(context.Background())
				require.NoError(t, err)
				e, err := model.QueryEntities().Only(context.Background())
				require.NoError(t, err)
				require.NoError(t, f.db.Entity.UpdateOne(e).SetType(999).Exec(context.Background()))
			}
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{folder}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			f.waitForStorageTask(t, accepted.ID, "error")
			count, err := f.db.RelocationItem.Query().Count(context.Background())
			require.NoError(t, err)
			require.Zero(t, count)
			objects := 2
			if kind == "unknown" {
				objects = 3
			}
			f.assertObjectCounts(t, objects, 0)
		})
	}
}

func TestStorageRelocationSnapshotExcludesLaterContentAcrossRestart(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "planned_tree", true: "empty_tree"}[empty], func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			folder := "cloudreve://my/snapshot"
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
			if !empty {
				f.upload(t, folder+"/original.txt", []byte("snapshot original"), nil)
			}
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{folder}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			if empty {
				f.waitForStorageTask(t, accepted.ID, "completed")
			} else {
				f.waitForRelocationItem(t, accepted.ID, relocationitem.StatePlanned)
			}
			w.stop(t)
			f.remote = ""
			f.login(t)
			f.upload(t, folder+"/later.txt", []byte("later content stays at source"), nil)
			id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
			require.NoError(t, err)
			header, err := f.db.RelocationPlan.Query().Where(relocationplan.TaskID(id)).Only(context.Background())
			require.NoError(t, err)
			count := len(header.FileIds)
			if empty {
				require.NoError(t, f.db.Task.UpdateOneID(id).SetStatus(task.StatusProcessing).Exec(context.Background()))
			}
			restarted := launchStorageWorkerWithWorkflows(t, f)
			f.remote = restarted.ready(t)
			f.login(t)
			f.waitForStorageTask(t, accepted.ID, "completed")
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), f.fileInfo(t, folder+"/later.txt").ExtendedInfo.Entities[0].StoragePolicy.ID)
			header, err = f.db.RelocationPlan.Query().Where(relocationplan.TaskID(id)).Only(context.Background())
			require.NoError(t, err)
			require.Len(t, header.FileIds, count)
			if !empty {
				require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), f.fileInfo(t, folder+"/original.txt").ExtendedInfo.Entities[0].StoragePolicy.ID)
			}
		})
	}
}
