package controllers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationplan"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationRevalidatesCurrentDestinationInsideTransaction(t *testing.T) {
	for _, boundary := range []string{"planning", "committing"} {
		for _, change := range []string{"grant", "pool-membership", "permission"} {
			t.Run(boundary+"/"+change, func(t *testing.T) {
				f := newStorageFixtureWithLegacy(t, true)
				if f.database.Type != "mysql" && f.database.Type != "postgres" {
					t.Skip("SQLite serializes writers; concurrent authorization runs in the database matrix")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				destination := f.policies[1].ID
				var pool *ent.StoragePolicy
				if change == "pool-membership" {
					pool = f.pool(t, 0, 1)
					pool.Edges.PolicyLoadBalance = pool.Edges.PolicyLoadBalance[1:]
					var err error
					pool, err = f.dep.StoragePolicyClient().Upsert(ctx, pool)
					require.NoError(t, err)
					destination = pool.ID
					// A separate grant to the child must not authorize a stale
					// selection from a pool that no longer contains that child.
					f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID, pool.ID)
				} else {
					f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
				}
				f.enableMigration(t, true)
				uri := "cloudreve://my/current-migration-grant.txt"
				data := []byte("a revoked destination must not receive committed references")
				f.upload(t, uri, data, nil)
				before := f.fileInfo(t, uri)
				usage := f.db.User.GetX(ctx, 2).Storage
				var accepted explorer.TaskResponse
				f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), destination)}, &accepted)
				taskID, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
				require.NoError(t, err)
				owner := f.db.User.Query().Where(user.ID(2)).WithGroup().OnlyX(ctx)
				ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
				ctx = context.WithValue(ctx, dependency.DepCtx{}, f.dep)
				ctx = context.WithValue(ctx, logging.LoggerCtx{}, f.dep.Logger())
				advance := func(ctx context.Context) (bool, error) {
					return relocation.AdvanceSingle(ctx, f.dep, taskID, owner.ID, []string{uri}, destination)
				}
				if boundary == "committing" {
					for range 2 {
						done, err := advance(ctx)
						require.NoError(t, err)
						require.False(t, done)
					}
					require.Equal(t, relocationitem.StateVerified, f.db.RelocationItem.Query().Where(relocationitem.TaskID(taskID)).OnlyX(ctx).State)
				}
				type probeKey struct{}
				entered, resume := make(chan struct{}), make(chan struct{})
				var paused atomic.Bool
				var release sync.Once
				defer release.Do(func() { close(resume) })
				f.db.Group.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						m := mutation.(*ent.GroupMutation)
						if _, ok := m.AddedMaxStorage(); ok && ctx.Value(probeKey{}) != nil && paused.CompareAndSwap(false, true) {
							// Establish an ordinary snapshot in this same native
							// transaction before the group authorization lock.
							if _, err := m.Client().GroupPolicy.Query().Where(grouppolicy.GroupID(2)).All(ctx); err != nil {
								return nil, err
							}
							close(entered)
							select {
							case <-resume:
							case <-ctx.Done():
								return nil, ctx.Err()
							}
						}
						return next.Mutate(ctx, mutation)
					})
				})
				result := make(chan error, 1)
				go func() {
					_, err := advance(context.WithValue(ctx, probeKey{}, true))
					result <- err
				}()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("migration did not reach the authorization boundary")
				}
				if change == "permission" {
					f.enableMigration(t, false)
				} else if pool == nil {
					f.assignPolicies(t, f.policies[0].ID)
				} else {
					pool.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: f.policies[0].ID, Weight: 1}}
					_, err := f.dep.StoragePolicyClient().Upsert(ctx, pool)
					require.NoError(t, err)
				}
				release.Do(func() { close(resume) })
				select {
				case err := <-result:
					require.Error(t, err, "migration must reject revoked authorization or selected pool membership")
				case <-ctx.Done():
					t.Fatal("migration did not finish after authorization changed")
				}
				after := f.fileInfo(t, uri)
				require.Equal(t, before.ID, after.ID)
				require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
				require.Equal(t, before.ExtendedInfo.Entities[0].StoragePolicy.ID, after.ExtendedInfo.Entities[0].StoragePolicy.ID)
				require.Equal(t, usage, f.db.User.GetX(ctx, 2).Storage)
				require.Equal(t, data, f.readFile(t, uri))
				if boundary == "planning" {
					require.Zero(t, f.db.RelocationPlan.Query().Where(relocationplan.TaskID(taskID)).CountX(ctx))
					require.Zero(t, f.db.RelocationItem.Query().Where(relocationitem.TaskID(taskID)).CountX(ctx))
					f.assertObjectCounts(t, 2, 0)
				} else {
					require.Equal(t, relocationitem.StateFailed, f.db.RelocationItem.Query().Where(relocationitem.TaskID(taskID)).OnlyX(ctx).State)
					f.assertObjectCounts(t, 2, 1)
				}
			})
		}
	}
}

func authenticateStorageMigration(t *testing.T, f *storageFixture, external bool) {
	t.Helper()
	if !external {
		f.login(t)
		return
	}
	if f.remote == "" {
		server := httptest.NewServer(f.router)
		defer server.Close()
		f.remote = server.URL
		defer func() { f.remote = "" }()
	}
	f.oidcLogin(t)
}

func TestStorageRelocationCanReadRevokedSourceAndKeepsCommittedTarget(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "oidc"}[external], func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			authenticateStorageMigration(t, f, external)
			originalToken := f.token
			uri := "cloudreve://my/revoked-source.txt"
			data := []byte("old source is readable even without new-write authorization")
			f.upload(t, uri, data, nil)
			before := f.fileInfo(t, uri)
			f.assignPolicies(t, f.policies[1].ID)
			f.token = originalToken
			require.Equal(t, data, f.readFile(t, uri))
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.token = originalToken
			f.waitForStorageTask(t, accepted.ID, "completed")
			f.assignPolicies(t, f.policies[0].ID)
			f.token = originalToken
			require.Equal(t, data, f.readFile(t, uri))
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), after.ExtendedInfo.Entities[0].StoragePolicy.ID)
			f.waitForStorageTask(t, accepted.ID, "completed")
		})
	}
}

func TestStorageRelocationRechecksDestinationAfterPlanAndPut(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "oidc"}[external], func(t *testing.T) {
			for _, boundary := range []relocationitem.State{relocationitem.StatePlanned, relocationitem.StateVerified} {
				t.Run(string(boundary), func(t *testing.T) {
					f := newStorageFixtureWithLegacy(t, true)
					f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
					f.enableMigration(t, true)
					authenticateStorageMigration(t, f, external)
					originalToken := f.token
					uri := "cloudreve://my/revoked-target.txt"
					data := []byte("uncommitted content must not follow a revoked destination")
					f.upload(t, uri, data, nil)
					before := f.fileInfo(t, uri)
					var accepted explorer.TaskResponse
					f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
					w := launchStorageWorkerWithWorkflows(t, f)
					_ = w.ready(t)
					f.waitForRelocationItem(t, accepted.ID, boundary)
					// Revoke from the issuing process so the running worker retains
					// its old Task owner and any old navigation state.
					f.assignPolicies(t, f.policies[0].ID)
					f.remote = w.ready(t)
					f.token = originalToken
					f.waitForStorageTask(t, accepted.ID, "error")
					after := f.fileInfo(t, uri)
					require.Equal(t, before.ID, after.ID)
					require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
					require.Equal(t, before.ExtendedInfo.Entities[0].StoragePolicy.ID, after.ExtendedInfo.Entities[0].StoragePolicy.ID)
					require.Equal(t, data, f.readFile(t, uri))
					if boundary == relocationitem.StatePlanned {
						f.assertObjectCounts(t, 2, 0)
					} else {
						f.assertObjectCounts(t, 2, 1)
					}
				})
			}
		})
	}
}
