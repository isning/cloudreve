package controllers_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/stretchr/testify/require"
)

func TestAuditPolicyBindingPreservesNamesAndRollsBackOnRecordFailure(t *testing.T) {
	for _, asAdmin := range []bool{false, true} {
		name := "owner"
		if asAdmin {
			name = "administrator"
		}
		t.Run(name, func(t *testing.T) {
			f := newAuditFixture(t)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			uri := "cloudreve://my/bound"
			f.upload(t, uri+"/file.txt", []byte("existing content"), nil)
			info := f.fileInfo(t, uri)
			id, err := f.dep.HashIDEncoder().Decode(info.ID, hashid.FileID)
			require.NoError(t, err)
			original := f.db.File.GetX(context.Background(), id).StoragePolicyFiles
			policy := f.policies[1]
			encoded := hashid.EncodePolicyID(f.dep.HashIDEncoder(), policy.ID)
			bind := func(policyID int) int {
				if asAdmin {
					f.loginAs(t, "storage-admin@example.com", f.adminPassword)
					var detail map[string]any
					f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/file/%d", id), nil, &detail)
					detail["storage_policy_files"] = policyID
					return f.responseCode(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/file/%d", id), map[string]any{"file": detail})
				}
				f.login(t)
				return f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{
					"uri": uri, "policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), policyID),
				})
			}
			require.Zero(t, bind(policy.ID))
			require.NoError(t, f.db.StoragePolicy.UpdateOneID(policy.ID).SetName("Renamed after binding").Exec(context.Background()))
			require.Zero(t, bind(policy.ID), "repeating the same binding must not create another mount event")

			f.login(t)
			var activities struct {
				Activities []struct {
					Content types.LogEntry `json:"content"`
				} `json:"activities"`
			}
			f.request(t, http.MethodGet, "/api/v4/file/activities?uri="+url.QueryEscape(uri)+"&page_size=20", nil, &activities)
			mounts := 0
			for _, activity := range activities.Activities {
				if activity.Content.Category == types.AuditMount {
					mounts++
					require.Equal(t, encoded, activity.Content.StoragePolicyID)
					require.Equal(t, policy.Name, activity.Content.StoragePolicy, "the Pro renderer consumes the historical policy name")
				}
			}
			require.Equal(t, 1, mounts)

			f.db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
				return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
					if kind, ok := m.Field("type"); ok && kind == int(types.AuditMount) {
						return nil, errors.New("injected mount audit failure")
					}
					return next.Mutate(ctx, m)
				})
			})
			require.NotZero(t, bind(f.policies[0].ID))
			require.Equal(t, policy.ID, f.db.File.GetX(context.Background(), id).StoragePolicyFiles)
			require.NotEqual(t, original, f.db.File.GetX(context.Background(), id).StoragePolicyFiles)

			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			var logs struct {
				Logs []struct {
					UserID  int            `json:"user_id"`
					Content types.LogEntry `json:"content"`
				} `json:"logs"`
			}
			f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{
				"page": 1, "page_size": 20, "conditions": map[string]string{
					"audit_log_file": fmt.Sprint(id), "audit_log_category": fmt.Sprint(types.AuditMount),
				},
			}, &logs)
			require.Len(t, logs.Logs, 1, "failed and unchanged bindings must not leave successful mount records")
			require.Equal(t, policy.Name, logs.Logs[0].Content.StoragePolicy)
			actor := 2
			if asAdmin {
				actor = 1
			}
			require.Equal(t, actor, logs.Logs[0].UserID)
		})
	}
}
