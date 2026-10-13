package controllers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationRejectsInvalidContractsAndSources(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.enableMigration(t, true)
	src := "cloudreve://my/valid.txt"
	f.upload(t, src, []byte("valid complete source remains readable"), nil)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	for _, body := range []map[string]any{
		{"src": nil, "dst_policy_id": a},
		{"src": []string{}, "dst_policy_id": a},
		{"src": []string{src}},
		{"src": []string{src}, "dst_policy_id": nil},
		{"src": []string{src}, "dst_policy_id": ""},
		{"src": []string{src}, "dst_policy_id": "invalid"},
		{"src": []string{src}, "dst_policy_id": f.policies[0].ID},
		{"src": []string{src}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), 999999)},
		{"src": []string{src}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)},
	} {
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", body))
	}
	for _, uri := range []string{"", "invalid", "cloudreve://my/missing", "cloudreve://trash/valid.txt", "cloudreve://share/unknown", "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 1) + "@my/valid.txt"} {
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": a}))
	}
	var pending explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/pending.txt", "size": 17}, &pending)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/pending.txt"}, "dst_policy_id": a}))
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/shortcut", "type": "folder"}, nil)
	_, err := f.db.File.Update().Where(file.OwnerID(2), file.Name("shortcut")).SetIsSymbolic(true).Save(context.Background())
	require.NoError(t, err)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/shortcut"}, "dst_policy_id": a}))
	var list explorer.TaskListResponse
	f.request(t, http.MethodGet, "/api/v4/workflow?category=general&page_size=100", nil, &list)
	require.Empty(t, list.Tasks)
	f.assertObjectCounts(t, 2, 0)
	require.Equal(t, []byte("valid complete source remains readable"), f.readFile(t, src))
}

func TestStorageRelocationPlanningRejectsIncompleteAndUnknownEntities(t *testing.T) {
	for _, changed := range []string{"unknown", "incomplete"} {
		t.Run(changed, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.enableMigration(t, true)
			src := "cloudreve://my/planning.txt"
			data := []byte("source remains intact when queued planning fails")
			f.upload(t, src, data, nil)
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{src}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)}, &accepted)
			entry, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("planning.txt")).Only(context.Background())
			require.NoError(t, err)
			entity, err := entry.QueryEntities().Only(context.Background())
			require.NoError(t, err)
			if changed == "unknown" {
				_, err = f.db.Entity.UpdateOne(entity).SetType(999).Save(context.Background())
				require.NoError(t, err)
			} else {
				var pending explorer.UploadSessionResponse
				f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": src, "size": 17, "entity_type": "version"}, &pending)
			}
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			failed := f.waitForStorageTask(t, accepted.ID, "error")
			require.NotEmpty(t, failed.Error)
			f.assertObjectCounts(t, 2, 0)
			if changed == "unknown" {
				_, err = f.db.Entity.UpdateOne(entity).SetType(entity.Type).Save(context.Background())
				require.NoError(t, err)
			}
			require.Equal(t, data, f.readFile(t, src))
		})
	}
}
