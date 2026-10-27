package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) createStorageGroup(t *testing.T) *ent.Group {
	t.Helper()
	input := f.groupDetail(t)
	input["id"], input["name"] = 0, "Additional storage group"
	var created ent.Group
	f.request(t, http.MethodPut, "/api/v4/admin/group", map[string]any{"group": input, "policy_ids": []int{f.policies[0].ID}}, &created)
	return &created
}

func TestStorageUserUpdatesInheritCurrentAndPendingUsers(t *testing.T) {
	for _, visibility := range []string{"committed", "pending"} {
		for _, change := range []string{"changed", "unchanged"} {
			for _, finish := range []string{"commit", "rollback"} {
				t.Run(visibility+"/"+change+"/"+finish, func(t *testing.T) {
					f := newWritableShareFixture(t)
					if visibility == "committed" && f.database.Type == "sqlite" {
						t.Skip("SQLite keeps the caller's sole connection")
					}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
					require.NoError(t, err)
					defer inventory.Rollback(tx)
					const email = "inherited-user-update@example.com"
					require.Zero(t, writer.GetClient().User.Query().Where(entuser.Email(email)).CountX(txCtx))
					createCtx := ctx
					if visibility == "pending" {
						createCtx = txCtx
					}
					created, err := f.dep.UserClient().Create(createCtx, &inventory.NewUserArgs{
						Email: email, Nick: "Original nickname", GroupID: 2, Status: entuser.StatusActive, SkipBootstrap: true,
					})
					require.NoError(t, err)
					// Native timestamp precision can leave lifecycle and scalar updates unchanged.
					f.db.User.Use(func(next ent.Mutator) ent.Mutator {
						return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
							m := mutation.(*ent.UserMutation)
							m.SetUpdatedAt(created.UpdatedAt)
							return next.Mutate(ctx, mutation)
						})
					})
					input := *created
					if change == "changed" {
						input.Nick, input.GroupUsers = "Updated nickname", 1
					}
					updated, err := f.dep.UserClient().Upsert(txCtx, &input, "", "")
					require.NoError(t, err)
					require.Equal(t, input.Nick, updated.Nick)
					require.Equal(t, input.GroupUsers, updated.GroupUsers)
					if finish == "commit" {
						require.NoError(t, inventory.Commit(tx))
					} else {
						require.NoError(t, inventory.Rollback(tx))
					}
					persisted, err := f.db.User.Get(ctx, created.ID)
					if finish == "rollback" && visibility == "pending" {
						require.True(t, ent.IsNotFound(err), "ordinary Upsert must not commit the caller's pending user")
						return
					}
					require.NoError(t, err)
					expected := &input
					if finish == "rollback" {
						expected = created
					}
					require.Equal(t, expected.Nick, persisted.Nick)
					require.Equal(t, expected.GroupUsers, persisted.GroupUsers)
				})
			}
		}
	}
}

func TestStorageGroupDeletionRechecksUsersAfterHTTPPreflight(t *testing.T) {
	f := newWritableShareFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	target := f.createStorageGroup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ready, resume := make(chan struct{}), make(chan struct{})
	var paused, released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(resume)
		}
	}
	defer release()
	f.db.User.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			value, err := next.Query(ctx, query)
			request, _ := ctx.Value(gin.ContextKey).(*gin.Context)
			if count, ok := value.(int); ok && count == 0 && err == nil && request != nil && request.Request.Method == http.MethodDelete && paused.CompareAndSwap(false, true) {
				close(ready)
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return value, err
		})
	}))
	deleted := make(chan int, 1)
	go func() {
		response := openIDRequest(t, f.router, http.MethodDelete, fmt.Sprintf("/api/v4/admin/group/%d", target.ID), nil, nil, f.token)
		var result struct{ Code int }
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			deleted <- -1
			return
		}
		deleted <- result.Code
	}()
	awaitPermissionPause(t, ready)
	member := f.db.User.GetX(ctx, 2)
	member.GroupUsers = target.ID
	f.request(t, http.MethodPut, "/api/v4/admin/user/2", map[string]any{"user": member}, nil)
	require.Equal(t, target.ID, f.db.User.GetX(ctx, 2).GroupUsers)
	release()
	require.EqualValues(t, serializer.CodeGroupUsedByUser, <-deleted)
	current, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
	require.NoError(t, err)
	require.NotNil(t, current.Edges.Group)
	require.Equal(t, target.ID, current.Edges.Group.ID)
	require.Equal(t, 1, f.db.GroupPolicy.Query().Where(grouppolicy.GroupID(target.ID)).CountX(ctx))
}

func TestStorageGroupAssignmentHoldsItsFenceUntilCommit(t *testing.T) {
	f := newWritableShareFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	target := f.createStorageGroup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type assignment struct{}
	ready, resume := make(chan struct{}), make(chan struct{})
	var paused, released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(resume)
		}
	}
	defer release()
	f.db.User.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			marked, _ := ctx.Value(assignment{}).(bool)
			groupID, hasGroup := mutation.Field(entuser.FieldGroupUsers)
			if marked && hasGroup && groupID == target.ID && paused.CompareAndSwap(false, true) {
				close(ready)
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	member := f.db.User.GetX(ctx, 2)
	member.GroupUsers = target.ID
	updated := make(chan error, 1)
	go func() {
		_, err := f.dep.UserClient().Upsert(context.WithValue(ctx, assignment{}, true), member, "", "")
		updated <- err
	}()
	awaitPermissionPause(t, ready)
	deleteCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	defer stop()
	require.Error(t, f.dep.GroupClient().Delete(deleteCtx, target.ID), "retirement must wait for the pending native assignment")
	release()
	require.NoError(t, <-updated)
	require.Equal(t, target.ID, f.db.User.GetX(ctx, 2).GroupUsers)
	require.EqualValues(t, serializer.CodeGroupUsedByUser, f.responseCode(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/group/%d", target.ID), nil))
	require.Equal(t, 1, f.db.GroupPolicy.Query().Where(grouppolicy.GroupID(target.ID)).CountX(ctx))
}

func TestStorageGroupDeletionChecksInheritedMembership(t *testing.T) {
	for _, kind := range []string{"committed", "pending"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "committed" && os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
				t.Skip("MySQL repeatable-read committed membership")
			}
			f := newWritableShareFixture(t)
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			target := f.createStorageGroup(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.GroupClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Zero(t, writer.GetClient().User.Query().Where(entuser.GroupUsers(target.ID)).CountX(txCtx))
			if kind == "pending" {
				_, err = f.dep.UserClient().Create(txCtx, &inventory.NewUserArgs{Email: "pending-group-member@example.com", Nick: "Pending member", GroupID: target.ID, Status: entuser.StatusActive, SkipBootstrap: true})
				require.NoError(t, err)
			} else {
				member := f.db.User.GetX(ctx, 2)
				member.GroupUsers = target.ID
				f.request(t, http.MethodPut, "/api/v4/admin/user/2", map[string]any{"user": member}, nil)
			}
			err = f.dep.GroupClient().Delete(txCtx, target.ID)
			var occupied *inventory.GroupInUseError
			require.ErrorAs(t, err, &occupied)
			require.Equal(t, 1, occupied.Count)
			require.NoError(t, inventory.Commit(tx), "rejected deletion preserves caller-owned pending membership")
			_, err = f.db.Group.Get(ctx, target.ID)
			require.NoError(t, err)
			require.Equal(t, 1, f.db.User.Query().Where(entuser.GroupUsers(target.ID)).CountX(ctx))
			require.Equal(t, 1, f.db.GroupPolicy.Query().Where(grouppolicy.GroupID(target.ID)).CountX(ctx))
		})
	}
}

func TestStorageUserAssignmentRejectsDeletedGroups(t *testing.T) {
	for _, kind := range []string{"native-create", "admin-create", "admin-update"} {
		t.Run(kind, func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			target := f.createStorageGroup(t)
			f.request(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/group/%d", target.ID), nil, nil)
			ctx := context.Background()
			member := f.db.User.GetX(ctx, 2)
			if kind == "native-create" {
				_, err := f.dep.UserClient().Create(ctx, &inventory.NewUserArgs{Email: "retired-group@example.com", Nick: "Retired group", GroupID: target.ID, Status: member.Status, SkipBootstrap: true})
				require.Error(t, err)
			} else {
				member.GroupUsers = target.ID
				if kind == "admin-create" {
					member.ID = 0
					member.Email = "retired-group@example.com"
				}
				_, err := f.dep.UserClient().Upsert(ctx, member, f.password, "")
				require.Error(t, err)
			}
			require.Equal(t, 2, f.db.User.GetX(ctx, 2).GroupUsers)
			require.Zero(t, f.db.User.Query().Where(entuser.GroupUsers(target.ID)).CountX(ctx))
		})
	}
}

func TestStorageConcurrentGroupCreationUsesIndependentGrants(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers; concurrent creation runs in the database matrix")
	}
	f := newStorageFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source := f.groupDetail(t)
	ready, resume := make(chan struct{}, 2), make(chan struct{})
	f.db.GroupPolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(writeCtx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if mutation.Op().Is(ent.OpCreate) {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(writeCtx, mutation)
		})
	})
	done := make(chan error, 2)
	for _, policy := range f.policies {
		input := make(map[string]any, len(source))
		for key, value := range source {
			input[key] = value
		}
		input["id"], input["name"] = 0, policy.Name
		go func() {
			w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/admin/group", map[string]any{"group": input, "policy_ids": []int{policy.ID}}, nil, f.token)
			var envelope struct {
				Code int
				Data struct{ ID int }
			}
			err := json.Unmarshal(w.Body.Bytes(), &envelope)
			if err == nil && (w.Code != http.StatusOK || envelope.Code != 0) {
				err = fmt.Errorf("group creation failed: HTTP %d, code %d", w.Code, envelope.Code)
			}
			if err == nil {
				var grant *ent.GroupPolicy
				grant, err = f.db.GroupPolicy.Query().Where(grouppolicy.GroupID(envelope.Data.ID)).Only(ctx)
				if err == nil && grant.StoragePolicyID != policy.ID {
					err = fmt.Errorf("group creation assigned policy %d instead of %d", grant.StoragePolicyID, policy.ID)
				}
			}
			done <- err
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(resume)
	for range 2 {
		require.NoError(t, <-done)
	}
}

func (f *storageFixture) groupDetail(t *testing.T) map[string]any {
	t.Helper()
	var detail map[string]any
	f.request(t, http.MethodGet, "/api/v4/admin/group/2", nil, &detail)
	return detail["group"].(map[string]any)
}

func (f *storageFixture) assignPolicies(t *testing.T, ids ...int) {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	delete(group, "edges")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": ids}, nil)
	f.login(t)
}

func (f *storageFixture) readFile(t *testing.T, uri string) []byte {
	t.Helper()
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}}, &links)
	require.Len(t, links.Urls, 1)
	_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	return data
}

func TestStorageReorderedDefaultWritesWithoutMovingOldContent(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	first := []byte("before reorder remains in bucket A")
	f.upload(t, "cloudreve://my/before.txt", first, nil)
	var before explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/before.txt"), nil, &before)
	f.assignPolicies(t, f.policies[1].ID, f.policies[0].ID)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), policies[0].ID)
	next := []byte("after reorder goes to bucket B")
	session := f.upload(t, "cloudreve://my/after.txt", next, nil)
	require.Equal(t, policies[0].ID, session.StoragePolicy.ID)
	require.Equal(t, first, f.readFile(t, "cloudreve://my/before.txt"))
	require.Equal(t, next, f.readFile(t, "cloudreve://my/after.txt"))
	var after explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/before.txt"), nil, &after)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.ExtendedInfo.Entities, after.ExtendedInfo.Entities)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(first)+len(next), capacity.Used)
	for _, policy := range f.policies {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
		require.NoError(t, err)
		require.Len(t, objects.Contents, 1)
	}
}

func (f *storageFixture) assertGroupPolicies(t *testing.T, ids ...int) {
	t.Helper()
	var detail struct {
		PolicyIDs []int `json:"policy_ids"`
		Group     struct {
			StoragePolicyID int `json:"storage_policy_id"`
		} `json:"group"`
	}
	f.request(t, http.MethodGet, "/api/v4/admin/group/2", nil, &detail)
	require.Equal(t, ids, detail.PolicyIDs)
	require.Equal(t, ids[0], detail.Group.StoragePolicyID)
}

func (f *storageFixture) rejectGroupUpdate(t *testing.T, body any) {
	t.Helper()
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/admin/group/2", body, nil, f.token)
	var envelope struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	require.Equal(t, serializer.CodeParamErr, envelope.Code)
}

func TestStorageAmbiguousAssignmentsLeaveGroupUnchanged(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	for _, value := range []any{nil, []int{}, []int{a, a}, []int{a, 9999999}, []int{-1}, []string{"invalid"}} {
		group := f.groupDetail(t)
		group["name"] = "must not partially save"
		f.rejectGroupUpdate(t, map[string]any{"group": group, "policy_ids": value})
		f.assertGroupPolicies(t, a, b)
		require.NotEqual(t, "must not partially save", f.groupDetail(t)["name"])
	}
	group := f.groupDetail(t)
	group["edges"] = map[string]any{"storage_policies": map[string]any{"id": b}}
	// The canonical list determines the default, independently of old display fields.
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": []int{a, b}}, nil)
	f.assertGroupPolicies(t, a, b)
	delete(group, "edges")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": []int{b, a}}, nil)
	f.assertGroupPolicies(t, b, a)
}

func TestStorageOrdinaryGroupEditsPreserveGrantsAndSettings(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	// Updating ordinary settings without a new list preserves current grants.
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["name"] = "legacy single-policy edit"
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.assertGroupPolicies(t, a)
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group = f.groupDetail(t)
	group["name"] = "legacy multi-policy edit"
	group["speed_limit"] = 8192
	// Omitted legacy default must preserve the actual default too.
	delete(group, "edges")
	delete(group, "storage_policy_id")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.assertGroupPolicies(t, a, b)
	reopened := f.groupDetail(t)
	require.Equal(t, "legacy multi-policy edit", reopened["name"])
	require.EqualValues(t, 8192, reopened["speed_limit"])
	f.login(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), a), policies[0].ID)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), b), policies[1].ID)
}

func TestStorageUnassignedGroupEditsPreserveEmptyGrants(t *testing.T) {
	f := newStorageFixture(t)
	ctx := context.Background()
	c := f.dep.DBClient()
	// A legacy group with no valid destination remains unassigned on upgrade.
	c.GroupPolicy.Delete().Where(grouppolicy.GroupID(2)).ExecX(ctx)
	c.Group.UpdateOneID(2).ClearStoragePolicies().ExecX(ctx)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["name"] = "Unassigned members"
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	require.Equal(t, "Unassigned members", f.groupDetail(t)["name"])
	require.Zero(t, c.Group.GetX(ctx, 2).StoragePolicyID)
	require.Zero(t, c.GroupPolicy.Query().Where(grouppolicy.GroupID(2)).CountX(ctx))
}

func TestStorageDefaultsAreDerivedOnlyFromOrderedGrants(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["edges"] = map[string]any{"storage_policies": map[string]any{"id": b}}
	// Neither the old edge nor the old scalar can change authorization.
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.assertGroupPolicies(t, a, b)
	group = f.groupDetail(t)
	for _, clear := range []any{nil, map[string]any{"id": 0}} {
		group["edges"] = map[string]any{"storage_policies": clear}
		f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
		f.assertGroupPolicies(t, a, b)
	}
	delete(group, "edges")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": []int{b}}, nil)
	f.assertGroupPolicies(t, b)
	f.login(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), b), policies[0].ID)
}

func TestStoragePolicyGroupsFollowNonDefaultGrantsAndRevocation(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	assertViews := func(expected bool) {
		t.Helper()
		var detail struct {
			Edges struct {
				Groups []struct {
					ID int `json:"id"`
				} `json:"groups"`
			} `json:"edges"`
		}
		f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/policy/%d", b), nil, &detail)
		require.Equal(t, expected, len(detail.Edges.Groups) > 0)
		if expected {
			require.Equal(t, 2, detail.Edges.Groups[0].ID)
		}
		var list struct {
			Policies []struct {
				ID    int `json:"id"`
				Edges struct {
					Groups []struct {
						ID int `json:"id"`
					} `json:"groups"`
				} `json:"edges"`
			} `json:"policies"`
		}
		f.request(t, http.MethodPost, "/api/v4/admin/policy", map[string]any{"page": 1, "page_size": 20, "order_by": "id", "order_direction": "asc"}, &list)
		found := false
		for _, policy := range list.Policies {
			if policy.ID == b {
				found = true
				require.Equal(t, expected, len(policy.Edges.Groups) > 0)
			}
		}
		require.True(t, found)
	}
	assertViews(true)
	// Saving the policy must return the same complete associations.
	var policy map[string]any
	f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/policy/%d", b), nil, &policy)
	f.request(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/policy/%d", b), map[string]any{"policy": policy}, &policy)
	require.NotEmpty(t, policy["edges"].(map[string]any)["groups"])
	// A live secondary grant protects deletion just like a default grant.
	require.Equal(t, serializer.CodePolicyUsedByGroups, f.responseCode(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", b), nil))
	f.assignPolicies(t, b, a)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	assertViews(true)
	f.assignPolicies(t, a)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	assertViews(false)
}

func TestStorageCreatesAndCopiesCanonicalGroupPolicies(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[1].ID, f.policies[0].ID)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	source := f.groupDetail(t)
	source["id"] = 0
	source["name"] = "Copied ordered group"
	var copied struct {
		ID        int   `json:"id"`
		PolicyIDs []int `json:"policy_ids"`
	}
	f.request(t, http.MethodPut, "/api/v4/admin/group", map[string]any{"group": source, "policy_ids": []int{f.policies[1].ID, f.policies[0].ID}}, &copied)
	require.Greater(t, copied.ID, 3)
	require.Equal(t, []int{f.policies[1].ID, f.policies[0].ID}, copied.PolicyIDs)
	var reopened struct {
		PolicyIDs []int `json:"policy_ids"`
	}
	f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/group/%d", copied.ID), nil, &reopened)
	require.Equal(t, copied.PolicyIDs, reopened.PolicyIDs)
	// New groups need an explicit canonical list; an old default is insufficient.
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/admin/group", map[string]any{"group": source}, nil, f.token)
	var result struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Equal(t, serializer.CodeParamErr, result.Code)
	// The system anonymous group can retain its native empty destination set.
	var anonymous map[string]any
	f.request(t, http.MethodGet, "/api/v4/admin/group/3", nil, &anonymous)
	f.request(t, http.MethodPut, "/api/v4/admin/group/3", map[string]any{"group": anonymous["group"], "policy_ids": []int{}}, &anonymous)
	require.Empty(t, anonymous["policy_ids"])
}

func TestStorageRetiredGroupReleasesPolicyGrants(t *testing.T) {
	f := newStorageFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var created struct {
		ID int `json:"id"`
	}
	group := f.groupDetail(t)
	group["name"] = "Disposable unused group"
	group["id"] = 0
	f.request(t, http.MethodPut, "/api/v4/admin/group", map[string]any{"group": group, "policy_ids": []int{f.policies[0].ID, f.policies[1].ID}}, &created)
	require.Greater(t, created.ID, 3)
	policyPath := fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, policyPath, nil), "a live extra grant prevents deleting its policy")
	f.request(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/group/%d", created.ID), nil, nil)
	grants, err := f.db.GroupPolicy.Query().Where(grouppolicy.GroupID(created.ID)).Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, grants, "retired groups release formal grants")
	require.NotZero(t, f.responseCode(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/group/%d", created.ID), nil))
	f.request(t, http.MethodDelete, policyPath, nil, nil)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/group/1", nil), "system group remains protected")
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/group/2", nil), "a group with members remains protected")
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/policy/1", nil), "system/default policy remains protected")
}
