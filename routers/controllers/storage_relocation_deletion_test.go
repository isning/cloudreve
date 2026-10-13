package controllers_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationDeletionKeepsForeignCopyAndCompensation(t *testing.T) {
	for _, account := range []bool{false, true} {
		t.Run(map[bool]string{false: "file_deleted", true: "account_deleted"}[account], func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			memberToken := f.token
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			group := f.groupDetail(t)
			group["settings"] = map[string]any{"max_walked_files": 10000}
			f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/foreign-copies", "type": "folder"}, nil)
			adminFolder, err := f.db.File.Query().Where(file.OwnerID(1), file.Name("foreign-copies")).Only(context.Background())
			require.NoError(t, err)
			f.token = memberToken
			uri := "cloudreve://my/existing.txt"
			payload := []byte("persisted object before storage extension")
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/copies", "type": "folder"}, nil)
			f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{uri}, "dst": "cloudreve://my/copies", "copy": true}, nil)
			copy, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("existing.txt"), file.FileChildrenNEQ(adminFolder.ID)).Order(file.ByID()).All(context.Background())
			require.NoError(t, err)
			require.Len(t, copy, 2)
			// No public ownership-transfer API exists. A controlled administrative
			// ownership change places this real native copy under another live owner.
			tx, err := f.db.Tx(context.Background())
			require.NoError(t, err)
			require.NoError(t, tx.File.UpdateOne(copy[1]).SetOwnerID(1).SetParentID(adminFolder.ID).Exec(context.Background()))
			require.NoError(t, tx.User.UpdateOneID(1).AddStorage(int64(len(payload))).Exec(context.Background()))
			require.NoError(t, tx.User.UpdateOneID(2).AddStorage(-int64(len(payload))).Exec(context.Background()))
			require.NoError(t, tx.Commit())
			before := f.fileInfo(t, uri)
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			first := launchStorageWorkerWithWorkflows(t, f)
			_ = first.ready(t)
			item := f.waitForRelocationItem(t, accepted.ID, relocationitem.StateVerified)
			first.stop(t)
			f.assertObjectCounts(t, 1, 1)
			if account {
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
				f.request(t, http.MethodPost, "/api/v4/admin/user/batch/delete", map[string]any{"ids": []int{2}}, nil)
				exists, err := f.db.User.Query().Where(user.ID(2)).Exist(context.Background())
				require.NoError(t, err)
				require.False(t, exists)
			} else {
				f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{uri}, "skip_soft_delete": true}, nil)
			}
			f.recycling = true
			restarted := launchStorageWorkerWithWorkflows(t, f)
			f.remote = restarted.ready(t)
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			require.Eventually(t, func() bool {
				current, err := f.db.RelocationItem.Get(context.Background(), item.ID)
				return err == nil && current.State == relocationitem.StateFailed && current.SourceCleanup == relocationitem.SourceCleanupRetained
			}, 45*time.Second, 50*time.Millisecond)
			require.Eventually(t, func() bool {
				attempt, err := f.db.RelocationAttempt.Get(context.Background(), item.ActiveAttemptID)
				return err == nil && attempt.Cleanup == relocationattempt.CleanupCleaned
			}, 45*time.Second, 50*time.Millisecond)
			original, err := f.db.File.Query().Where(file.ID(copy[0].ID)).Exist(context.Background())
			require.NoError(t, err)
			require.False(t, original)
			if account {
				exists, err := f.db.User.Query().Where(user.ID(2)).Exist(context.Background())
				require.NoError(t, err)
				require.False(t, exists)
			}
			foreignURI := "cloudreve://my/foreign-copies/existing.txt"
			foreign := f.fileInfo(t, foreignURI)
			require.Equal(t, before.PrimaryEntity, foreign.PrimaryEntity)
			require.Equal(t, payload, f.readFile(t, foreignURI))
			f.assertObjectCounts(t, 1, 0)
			var capacity fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
			require.EqualValues(t, len(payload), capacity.Used)
			if !account {
				f.login(t)
				require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri=cloudreve%3A%2F%2Fmy%2Fexisting.txt", nil))
			}
		})
	}
}
