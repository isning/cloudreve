package inventory

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/node"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestStoragePolicyLockLoadsNodeInCallerTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, raw, _, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	require.NoError(t, c.Schema.Create(ctx))
	n := c.Node.Create().SetName("Remote node").SetType(node.TypeSlave).SetStatus(node.StatusActive).
		SetServer("https://original-node.example.com").SetCapabilities(&boolset.BooleanSet{}).SaveX(ctx)
	p := c.StoragePolicy.Create().SetName("Remote destination").SetType(types.PolicyTypeRemote).SetNode(n).SaveX(ctx)
	writer, tx, txCtx, err := WithTx(ctx, NewStoragePolicyClient(c, nil))
	require.NoError(t, err)
	defer Rollback(tx)
	writer.GetClient().Node.UpdateOneID(n.ID).SetServer("https://pending-node.example.com").ExecX(txCtx)
	current, err := LockStoragePolicy(txCtx, writer.GetClient(), p.ID)
	require.NoError(t, err)
	require.NotNil(t, current.Edges.Node)
	require.Equal(t, "https://pending-node.example.com", current.Edges.Node.Server)
	require.NoError(t, Rollback(tx))
	require.Equal(t, n.Server, c.Node.GetX(ctx, n.ID).Server)
}

func TestLifecycleLocksSeeRowsCommittedAfterInheritedSnapshot(t *testing.T) {
	for _, kind := range []string{"policy", "owner", "group"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if driver != "mysql" {
				t.Skip("MySQL repeatable-read unchanged-row fallback")
			}
			require.NoError(t, c.Schema.Create(ctx))
			existing := c.Group.Create().SetName("Existing group").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
			writer, tx, txCtx, err := WithTx(ctx, NewStoragePolicyClient(c, nil))
			require.NoError(t, err)
			defer Rollback(tx)
			require.Equal(t, 1, writer.GetClient().Group.Query().CountX(txCtx))
			switch kind {
			case "policy":
				p := c.StoragePolicy.Create().SetName("New destination").SetType(types.PolicyTypeLocal).SetMaxSize(0).SaveX(ctx)
				stamp := c.StoragePolicy.GetX(ctx, p.ID).UpdatedAt
				c.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						m := mutation.(*ent.StoragePolicyMutation)
						if id, ok := m.ID(); ok && id == p.ID {
							m.SetUpdatedAt(stamp)
						}
						return next.Mutate(ctx, mutation)
					})
				})
				_, err = LockStoragePolicy(txCtx, writer.GetClient(), p.ID)
			case "owner":
				u := c.User.Create().SetEmail("new-owner@example.com").SetNick("New owner").SetStatus(user.StatusActive).SetGroupID(existing.ID).SaveX(ctx)
				stamp := c.User.GetX(ctx, u.ID).UpdatedAt
				c.User.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						m := mutation.(*ent.UserMutation)
						if id, ok := m.ID(); ok && id == u.ID {
							m.SetUpdatedAt(stamp)
						}
						return next.Mutate(ctx, mutation)
					})
				})
				err = LockActiveStorageOwner(txCtx, writer.GetClient(), u.ID)
			case "group":
				g := c.Group.Create().SetName("New group").SetPermissions(&boolset.BooleanSet{}).SetSpeedLimit(0).SaveX(ctx)
				stamp := c.Group.GetX(ctx, g.ID).UpdatedAt
				c.Group.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						m := mutation.(*ent.GroupMutation)
						if id, ok := m.ID(); ok && id == g.ID {
							m.SetUpdatedAt(stamp)
						}
						return next.Mutate(ctx, mutation)
					})
				})
				_, err = NewGroupClient(writer.GetClient(), "", nil).(*groupClient).lockGroup(txCtx, g.ID)
			}
			require.NoError(t, err)
			require.NoError(t, Commit(tx))
		})
	}
}

func TestGroupPolicyUpdateSeesGroupCommittedAfterInheritedSnapshot(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if driver != "mysql" {
				t.Skip("MySQL repeatable-read unchanged group update")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			require.NoError(t, c.Schema.Create(ctx))
			a := c.StoragePolicy.Create().SetName("A").SetType(types.PolicyTypeLocal).SaveX(ctx)
			b := c.StoragePolicy.Create().SetName("B").SetType(types.PolicyTypeLocal).SaveX(ctx)
			groups := NewGroupClient(c, "", nil)
			writer, tx, txCtx, err := WithTx(ctx, groups)
			require.NoError(t, err)
			defer Rollback(tx)
			_, err = writer.GetClient().Group.Query().Count(txCtx)
			require.NoError(t, err)
			ids := []int{a.ID}
			g, err := groups.UpsertWithPolicies(ctx, &ent.Group{Name: "New group", Permissions: &boolset.BooleanSet{}, Settings: &types.GroupSetting{}}, &ids)
			require.NoError(t, err)
			stamp := c.Group.GetX(ctx, g.ID).UpdatedAt
			c.Group.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					m := mutation.(*ent.GroupMutation)
					if id, ok := m.ID(); ok && id == g.ID {
						m.SetUpdatedAt(stamp)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			ids = []int{a.ID, b.ID}
			updated, err := writer.UpsertWithPolicies(txCtx, g, &ids)
			require.NoError(t, err)
			require.Equal(t, g.ID, updated.ID)
			grants := func(db *ent.Client) []int {
				rows := db.GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).Order(ent.Asc(grouppolicy.FieldPosition)).AllX(ctx)
				result := make([]int, 0, len(rows))
				for _, row := range rows {
					result = append(result, row.StoragePolicyID)
				}
				return result
			}
			require.Equal(t, ids, grants(writer.GetClient()))
			require.Equal(t, []int{a.ID}, grants(c), "caller retains the uncommitted write")
			if commit {
				require.NoError(t, Commit(tx))
				require.Equal(t, ids, grants(c))
			} else {
				require.NoError(t, Rollback(tx))
				require.Equal(t, []int{a.ID}, grants(c))
			}
		})
	}
}

func TestUnchangedPolicyAndShareUpdatesSeeCurrentRows(t *testing.T) {
	for _, kind := range []string{"policy", "pool", "share"} {
		for _, commit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/commit=%t", kind, commit), func(t *testing.T) {
				c, raw, driver, _ := migrationFixture(t)
				t.Cleanup(func() { require.NoError(t, raw.Close()) })
				if driver != "mysql" {
					t.Skip("MySQL repeatable-read unchanged update result")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				require.NoError(t, c.Schema.Create(ctx))
				marker := c.Setting.Create().SetName("caller_marker").SetValue("original").SaveX(ctx)
				g := c.Group.Create().SetName("Owners").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
				u := c.User.Create().SetEmail("owner@example.com").SetNick("Owner").SetStatus(user.StatusActive).SetGroupID(g.ID).SaveX(ctx)
				file := c.File.Create().SetName("Source").SetType(int(types.FileTypeFolder)).SetOwner(u).SaveX(ctx)
				child := c.StoragePolicy.Create().SetName("Child").SetType(types.PolicyTypeLocal).SaveX(ctx)
				policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
				shares := NewShareClient(c, "", nil)
				writer, tx, txCtx, err := WithTx(ctx, policies)
				require.NoError(t, err)
				defer Rollback(tx)
				_, err = writer.GetClient().Share.Query().Count(txCtx)
				require.NoError(t, err)
				writer.GetClient().Setting.UpdateOneID(marker.ID).SetValue("pending").ExecX(txCtx)
				if kind == "share" {
					expires := time.Now().Add(time.Hour).Truncate(time.Second)
					link, err := shares.Upsert(ctx, &CreateShareParams{OwnerID: u.ID, FileID: file.ID, RemainDownloads: 3, Expires: &expires, Props: &types.ShareProps{}})
					require.NoError(t, err)
					stored := c.Share.GetX(ctx, link.ID)
					c.Share.Use(func(next ent.Mutator) ent.Mutator {
						return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
							m := mutation.(*ent.ShareMutation)
							if id, ok := m.ID(); ok && id == stored.ID {
								m.SetUpdatedAt(stored.UpdatedAt)
							}
							return next.Mutate(ctx, mutation)
						})
					})
					current, err := shares.Upsert(txCtx, &CreateShareParams{OwnerID: u.ID, FileID: file.ID, Existed: stored, RemainDownloads: *stored.RemainDownloads, Expires: stored.Expires, Props: stored.Props})
					require.NoError(t, err)
					require.Equal(t, stored.ID, current.ID)
					require.Equal(t, stored.RemainDownloads, current.RemainDownloads)
				} else {
					input := &ent.StoragePolicy{Name: "New destination", Type: types.PolicyTypeLocal}
					if kind == "pool" {
						input.Type = types.PolicyTypeLoadBalance
					}
					p, err := policies.Upsert(ctx, input)
					require.NoError(t, err)
					stamp := c.StoragePolicy.GetX(ctx, p.ID).UpdatedAt
					c.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
						return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
							m := mutation.(*ent.StoragePolicyMutation)
							if id, ok := m.ID(); ok && id == p.ID {
								m.SetUpdatedAt(stamp)
							}
							return next.Mutate(ctx, mutation)
						})
					})
					if kind == "pool" {
						p.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: child.ID, Weight: 1}}
					}
					current, err := writer.Upsert(txCtx, p)
					require.NoError(t, err)
					require.Equal(t, p.ID, current.ID)
					if kind == "pool" {
						require.Len(t, current.Edges.PolicyLoadBalance, 1)
						require.Equal(t, child.ID, current.Edges.PolicyLoadBalance[0].StoragePolicyID)
					}
				}
				require.Equal(t, "original", c.Setting.GetX(ctx, marker.ID).Value, "update must not commit its caller")
				require.Equal(t, "pending", writer.GetClient().Setting.GetX(txCtx, marker.ID).Value)
				if commit {
					require.NoError(t, Commit(tx))
					require.Equal(t, "pending", c.Setting.GetX(ctx, marker.ID).Value)
				} else {
					require.NoError(t, Rollback(tx))
					require.Equal(t, "original", c.Setting.GetX(ctx, marker.ID).Value)
				}
			})
		}
	}
}

func TestGroupPoliciesUpgradePreservesBindingsAndDoesNotReplay(t *testing.T) {
	for _, previous := range []string{"single-policy", "storage-v9"} {
		t.Run(previous, func(t *testing.T) {
			ctx := context.Background()
			c, raw, _, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			var tables []*schema.Table
			for _, table := range entmigrate.Tables {
				if previous == "storage-v9" || table.Name != "group_policies" {
					tables = append(tables, table)
				}
			}
			require.NoError(t, entmigrate.Create(ctx, c.Schema, tables, schema.WithAtlas(false)))
			a := c.StoragePolicy.Create().SetName("A").SetType(types.PolicyTypeLocal).SaveX(ctx)
			b := c.StoragePolicy.Create().SetName("B").SetType(types.PolicyTypeLocal).SaveX(ctx)
			legacy := c.Group.Create().SetName("Legacy").SetPermissions(&boolset.BooleanSet{}).SetStoragePolicyID(a.ID).SaveX(ctx)
			empty := c.Group.Create().SetName("No destination").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
			retired := c.Group.Create().SetName("Retired").SetPermissions(&boolset.BooleanSet{}).SetStoragePolicyID(a.ID).SetDeletedAt(time.Now()).SaveX(ctx)
			deleted := c.StoragePolicy.Create().SetName("Deleted").SetType(types.PolicyTypeLocal).SaveX(ctx)
			orphan := c.Group.Create().SetName("Obsolete destination").SetPermissions(&boolset.BooleanSet{}).SetStoragePolicyID(deleted.ID).SaveX(ctx)
			c.StoragePolicy.UpdateOne(deleted).SetDeletedAt(time.Now()).ExecX(ctx)
			var ordered *ent.Group
			if previous == "storage-v9" {
				ordered = c.Group.Create().SetName("Ordered").SetPermissions(&boolset.BooleanSet{}).SetStoragePolicyID(a.ID).SaveX(ctx)
				c.GroupPolicy.Create().SetGroupID(ordered.ID).SetStoragePolicyID(b.ID).SetPosition(0).SaveX(ctx)
				c.GroupPolicy.Create().SetGroupID(ordered.ID).SetStoragePolicyID(a.ID).SetPosition(1).SaveX(ctx)
				c.GroupPolicy.Create().SetGroupID(retired.ID).SetStoragePolicyID(a.ID).SetPosition(0).SaveX(ctx)
				c.Setting.Create().SetName("storage_extension_schema_v9").SetValue("complete").SaveX(ctx)
			}
			require.NoError(t, EnsureStorageSchema(ctx, c))
			policies := NewStoragePolicyClient(c, nil)
			available, err := policies.AvailableByGroup(ctx, legacy)
			require.NoError(t, err)
			require.Len(t, available, 1)
			require.Equal(t, a.ID, available[0].ID)
			require.Equal(t, 1, c.GroupPolicy.Query().Where(grouppolicy.GroupID(legacy.ID)).CountX(ctx))
			require.Zero(t, c.GroupPolicy.Query().Where(grouppolicy.GroupIDIn(empty.ID, retired.ID, orphan.ID)).CountX(ctx))
			require.Zero(t, c.Group.GetX(ctx, orphan.ID).StoragePolicyID)
			if ordered != nil {
				available, err := policies.AvailableByGroup(ctx, ordered)
				require.NoError(t, err)
				require.Len(t, available, 2)
				require.Equal(t, b.ID, available[0].ID)
				require.Equal(t, a.ID, available[1].ID)
				require.Equal(t, b.ID, c.Group.GetX(ctx, ordered.ID).StoragePolicyID)
				first, err := policies.GetByGroup(ctx, ordered)
				require.NoError(t, err)
				require.Equal(t, b.ID, first.ID)
			}
			// A completed migration must never recreate a subsequently removed grant,
			// even when an obsolete default value remains in the upstream column.
			c.GroupPolicy.Delete().Where(grouppolicy.GroupID(legacy.ID)).ExecX(ctx)
			require.NoError(t, EnsureStorageSchema(ctx, c))
			available, err = policies.AvailableByGroup(ctx, legacy)
			require.NoError(t, err)
			require.Empty(t, available)
		})
	}
}

func TestGroupPoliciesFreshInstallationUsesNativeInitialization(t *testing.T) {
	ctx := context.Background()
	c, raw, _, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	l := logging.NewConsoleLogger(logging.LevelError)
	kv := cache.NewMemoStore("", l)
	_, err := InitializeDBClient(l, c, kv, "4.14.0")
	require.NoError(t, err)
	require.NoError(t, EnsureStorageSchema(ctx, c))
	for _, id := range []int{1, 2, AnonymousGroupID} {
		g := c.Group.GetX(ctx, id)
		policies, err := NewStoragePolicyClient(c, kv).AvailableByGroup(ctx, g)
		require.NoError(t, err)
		if id == AnonymousGroupID {
			require.Empty(t, policies)
		} else {
			require.Len(t, policies, 1)
			require.Equal(t, 1, policies[0].ID)
		}
	}
	require.NoError(t, EnsureStorageSchema(ctx, c))
	require.Equal(t, 2, c.GroupPolicy.Query().CountX(ctx))
}

func TestGroupPoliciesUpgradeRollsBackAndResumes(t *testing.T) {
	ctx := context.Background()
	c, raw, _, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	require.NoError(t, c.Schema.Create(ctx))
	p := c.StoragePolicy.Create().SetName("A").SetType(types.PolicyTypeLocal).SaveX(ctx)
	for _, name := range []string{"One", "Two"} {
		c.Group.Create().SetName(name).SetPermissions(&boolset.BooleanSet{}).SetStoragePolicyID(p.ID).SaveX(ctx)
	}
	retired := c.Group.Create().SetName("Retired").SetPermissions(&boolset.BooleanSet{}).SetDeletedAt(time.Now()).SaveX(ctx)
	c.GroupPolicy.Create().SetGroupID(retired.ID).SetStoragePolicyID(p.ID).SetPosition(0).ExecX(ctx)
	injected := errors.New("injected group policy migration failure")
	var resumed atomic.Bool
	writes := 0
	c.GroupPolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if !m.Op().Is(ent.OpCreate) {
				return next.Mutate(ctx, m)
			}
			writes++
			if !resumed.Load() && writes == 2 {
				return nil, injected
			}
			return next.Mutate(ctx, m)
		})
	})
	require.ErrorIs(t, EnsureStorageSchema(ctx, c), injected)
	require.Equal(t, 1, c.GroupPolicy.Query().CountX(ctx), "retired-grant cleanup must roll back with the failed migration")
	require.Equal(t, retired.ID, c.GroupPolicy.Query().OnlyX(ctx).GroupID)
	require.False(t, c.Setting.Query().Where(setting.Name(StorageSchemaVersion)).ExistX(ctx))
	resumed.Store(true)
	require.NoError(t, EnsureStorageSchema(ctx, c))
	require.Equal(t, 2, c.GroupPolicy.Query().CountX(ctx))
	require.NoError(t, EnsureStorageSchema(ctx, c))
	require.Equal(t, 2, c.GroupPolicy.Query().CountX(ctx))
}

func TestPolicyGroupsUseCurrentGrantsWithoutPollutingCache(t *testing.T) {
	ctx := context.Background()
	c, raw, _, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	require.NoError(t, c.Schema.Create(ctx))
	a := c.StoragePolicy.Create().SetName("A").SetType(types.PolicyTypeLocal).SaveX(ctx)
	b := c.StoragePolicy.Create().SetName("B").SetType(types.PolicyTypeLocal).SaveX(ctx)
	g := c.Group.Create().SetName("Members").SetPermissions(&boolset.BooleanSet{}).SetStoragePolicyID(a.ID).SaveX(ctx)
	c.GroupPolicy.Create().SetGroupID(g.ID).SetStoragePolicyID(a.ID).SetPosition(0).SaveX(ctx)
	c.GroupPolicy.Create().SetGroupID(g.ID).SetStoragePolicyID(b.ID).SetPosition(1).SaveX(ctx)
	policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
	_, err := policies.GetPolicyByID(ctx, b.ID)
	require.NoError(t, err)
	withGroups := context.WithValue(ctx, LoadStoragePolicyGroup{}, true)
	assertGroups := func(id int, expected ...int) {
		t.Helper()
		p, err := policies.GetPolicyByID(withGroups, id)
		require.NoError(t, err)
		ids := make([]int, 0, len(p.Edges.Groups))
		for _, group := range p.Edges.Groups {
			ids = append(ids, group.ID)
		}
		require.Equal(t, append([]int{}, expected...), ids)
	}
	assertGroups(b.ID, g.ID)
	list, err := policies.ListPolicies(withGroups, &ListPolicyParameters{PaginationArgs: &PaginationArgs{PageSize: 20}})
	require.NoError(t, err)
	require.Len(t, list.Policies, 2)
	for _, p := range list.Policies {
		require.Len(t, p.Edges.Groups, 1)
		require.Equal(t, g.ID, p.Edges.Groups[0].ID)
	}
	plain, err := policies.GetPolicyByID(ctx, b.ID)
	require.NoError(t, err)
	require.Empty(t, plain.Edges.Groups, "admin associations stay out of the shared policy cache")
	// Only B is now granted; the stale default A must have no authority.
	c.GroupPolicy.Delete().Where(grouppolicy.GroupID(g.ID), grouppolicy.StoragePolicyID(a.ID)).ExecX(ctx)
	assertGroups(a.ID)
	assertGroups(b.ID, g.ID)
	c.Group.UpdateOne(g).SetDeletedAt(time.Now()).ExecX(ctx)
	assertGroups(b.ID)
	injected := errors.New("injected grant lookup failure")
	c.GroupPolicy.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(context.Context, ent.Query) (ent.Value, error) { return nil, injected })
	}))
	_, err = policies.GetPolicyByID(withGroups, b.ID)
	require.ErrorIs(t, err, injected)
	_, err = policies.ListPolicies(withGroups, &ListPolicyParameters{PaginationArgs: &PaginationArgs{PageSize: 20}})
	require.ErrorIs(t, err, injected)
}

func TestGroupPolicyWritesAndDeletionShareLifecycleLocks(t *testing.T) {
	for _, order := range []string{"grant-first", "delete-first"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			require.NoError(t, c.Schema.Create(ctx))
			p := c.StoragePolicy.Create().SetName("Destination").SetType(types.PolicyTypeLocal).SaveX(ctx)
			g := c.Group.Create().SetName("Members").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
			groups := NewGroupClient(c, "", nil)
			policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
			entered, release := make(chan struct{}), make(chan struct{})
			var paused atomic.Bool
			type probe struct{}
			// Pause only the marked writer at a real Ent mutation boundary.
			hook := func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
					if marked, _ := ctx.Value(probe{}).(bool); marked && paused.CompareAndSwap(false, true) {
						close(entered)
						select {
						case <-release:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					return next.Mutate(ctx, m)
				})
			}
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			marked := context.WithValue(ctx, probe{}, true)
			ids := []int{p.ID}
			write := func(ctx context.Context) error {
				scoped, outer, txCtx, err := WithTx(ctx, groups)
				if err != nil {
					return err
				}
				defer Rollback(outer)
				if _, err := scoped.UpsertWithPolicies(txCtx, g, &ids); err != nil {
					return err
				}
				return Commit(outer)
			}
			first, second := make(chan error, 1), make(chan error, 1)
			if order == "grant-first" {
				c.GroupPolicy.Use(hook)
				go func() { first <- write(marked) }()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				go func() { second <- policies.Delete(ctx, p) }()
				close(release)
				require.NoError(t, <-first)
				require.ErrorIs(t, <-second, ErrStoragePolicyGranted)
				require.True(t, c.StoragePolicy.Query().ExistX(ctx))
				require.Equal(t, 1, c.GroupPolicy.Query().CountX(ctx))
			} else {
				// On MySQL this also establishes an older repeatable-read snapshot
				// before the destination is deleted by the other transaction.
				c.StoragePolicy.Use(hook)
				if driver == "sqlite3" {
					go func() { first <- policies.Delete(marked, p) }()
				} else {
					go func() { first <- write(marked) }()
				}
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if driver == "sqlite3" {
					// SQLite serializes writers for the entire database.
					close(release)
					require.NoError(t, <-first)
					require.ErrorIs(t, write(ctx), ErrInvalidGroupPolicies)
				} else {
					require.NoError(t, policies.Delete(ctx, p))
					close(release)
					require.ErrorIs(t, <-first, ErrInvalidGroupPolicies)
				}
				require.Zero(t, c.GroupPolicy.Query().CountX(ctx))
			}
		})
	}
}

func TestGroupPolicyWritesFollowPoolEditLockOrder(t *testing.T) {
	for _, converting := range []bool{false, true} {
		t.Run(fmt.Sprintf("converting=%t", converting), func(t *testing.T) {
			testGroupPolicyWritesFollowPoolEditLockOrder(t, converting)
		})
	}
}

func testGroupPolicyWritesFollowPoolEditLockOrder(t *testing.T, converting bool) {
	ctx := context.Background()
	c, raw, driver, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	if driver == "sqlite3" {
		t.Skip("SQLite serializes database writers; row-lock ordering is exercised by the database matrix")
	}
	require.NoError(t, c.Schema.Create(ctx))
	child := c.StoragePolicy.Create().SetName("Child").SetType(types.PolicyTypeLocal).SaveX(ctx)
	poolType := types.PolicyTypeLoadBalance
	if converting {
		poolType = types.PolicyTypeLocal
	}
	pool := c.StoragePolicy.Create().SetName("Pool").SetType(poolType).SaveX(ctx)
	pool.Type = types.PolicyTypeLoadBalance
	pool.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: child.ID, Weight: 1}}
	if !converting {
		c.PolicyLoadBalance.Create().SetLoadBalanceID(pool.ID).SetStoragePolicyID(child.ID).SetWeight(1).SaveX(ctx)
	}
	g := c.Group.Create().SetName("Members").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
	type probe struct{}
	poolAtChild, groupAtPool, resume := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var poolPaused, groupEntered atomic.Bool
	c.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			m := mutation.(*ent.StoragePolicyMutation)
			id, _ := m.ID()
			if actor, _ := ctx.Value(probe{}).(string); actor == "pool" && id == child.ID && poolPaused.CompareAndSwap(false, true) {
				close(poolAtChild)
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			} else if actor == "group" && id == pool.ID && groupEntered.CompareAndSwap(false, true) {
				close(groupAtPool)
			}
			return next.Mutate(ctx, mutation)
		})
	})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
	poolDone, groupDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := policies.Upsert(context.WithValue(ctx, probe{}, "pool"), pool)
		poolDone <- err
	}()
	select {
	case <-poolAtChild:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		ids := []int{child.ID, pool.ID}
		_, err := NewGroupClient(c, "", nil).UpsertWithPolicies(context.WithValue(ctx, probe{}, "group"), g, &ids)
		groupDone <- err
	}()
	select {
	case <-groupAtPool:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	close(resume)
	require.NoError(t, <-poolDone)
	require.NoError(t, <-groupDone)
	require.Equal(t, 2, c.GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).CountX(ctx))
}

func TestPoolConversionRechecksDependenciesAfterPolicyLocks(t *testing.T) {
	for _, dependency := range []string{"membership", "entity", "relocation-plan", "relocation-attempt", "relocation-io"} {
		t.Run(dependency, func(t *testing.T) {
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if driver == "sqlite3" {
				t.Skip("SQLite serializes database writers; snapshot checks run in the database matrix")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			require.NoError(t, c.Schema.Create(ctx))
			child := c.StoragePolicy.Create().SetName("Child").SetType(types.PolicyTypeLocal).SaveX(ctx)
			parent := c.StoragePolicy.Create().SetName("Converting policy").SetType(types.PolicyTypeLocal).SaveX(ctx)
			parent.Type = types.PolicyTypeLoadBalance
			parent.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: child.ID, Weight: 1}}
			source := c.StoragePolicy.Create().SetName("Source").SetType(types.PolicyTypeLocal).SaveX(ctx)
			createItem := func(db *ent.Client) *ent.RelocationItem {
				return db.RelocationItem.Create().SetTaskID(1).SetOwnerID(1).SetSourceEntityID(1).
					SetSourcePolicyID(source.ID).SetSourceKey("existing").SetSourceLocation("source").
					SetDestinationPolicyID(parent.ID).SetDestinationLocation("destination").
					SetSnapshot(&types.RelocationSnapshot{}).SetReferences([]types.RelocationReference{}).
					SetSourceCleanup(relocationitem.SourceCleanupUnneeded).SaveX(ctx)
			}
			var previousAttempt *ent.RelocationAttempt
			if dependency == "relocation-io" {
				item := createItem(c)
				c.RelocationItem.UpdateOne(item).SetState(relocationitem.StateFailed).ExecX(ctx)
				previousAttempt = c.RelocationAttempt.Create().SetItemID(item.ID).SetFence(1).SetTargetKey("attempt").
					SetIoState(relocationattempt.IoStateEnded).SetCleanup(relocationattempt.CleanupCleaned).SaveX(ctx)
			}
			policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
			entered, resume := make(chan struct{}), make(chan struct{})
			var paused atomic.Bool
			type probe struct{}
			if dependency == "membership" {
				c.Setting.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						if marked, _ := ctx.Value(probe{}).(bool); marked && paused.CompareAndSwap(false, true) {
							// A different membership writer must finish before this
							// transaction takes the configuration fence.
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
			}
			c.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					id, _ := mutation.(*ent.StoragePolicyMutation).ID()
					if marked, _ := ctx.Value(probe{}).(bool); dependency != "membership" && marked && id == parent.ID && paused.CompareAndSwap(false, true) {
						// The lower-ID child lock has established a repeatable-read
						// snapshot, but the converting policy is not locked yet.
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
			done := make(chan error, 1)
			go func() {
				// Keep exercising inherited repeatable-read snapshots even though
				// standalone administration writes use read committed.
				client, tx, txCtx, err := WithTx(context.WithValue(ctx, probe{}, true), policies)
				if err == nil {
					defer Rollback(tx)
					_, err = client.GetClient().StoragePolicy.Query().Count(txCtx)
					if err == nil {
						_, err = client.Upsert(txCtx, parent)
					}
					if err == nil {
						err = Commit(tx)
					}
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			expected := ErrStoragePolicyInPool
			if dependency == "membership" {
				_, err := policies.Upsert(ctx, &ent.StoragePolicy{
					Name: "Outer pool", Type: types.PolicyTypeLoadBalance,
					Edges: ent.StoragePolicyEdges{PolicyLoadBalance: []*ent.PolicyLoadBalance{{StoragePolicyID: parent.ID, Weight: 1}}},
				})
				require.NoError(t, err)
			} else {
				tx, err := c.Tx(ctx)
				require.NoError(t, err)
				defer tx.Rollback()
				_, err = LockStoragePolicy(ctx, tx.Client(), parent.ID)
				require.NoError(t, err)
				if dependency == "entity" {
					expected = ErrInvalidLoadBalancePolicy
					require.NoError(t, tx.Entity.Create().SetType(0).SetSource("existing").SetSize(1).SetStoragePolicyEntities(parent.ID).Exec(ctx))
				} else {
					expected = ErrStoragePolicyInUse
					if previousAttempt != nil {
						require.NoError(t, tx.RelocationAttempt.UpdateOne(previousAttempt).SetIoState(relocationattempt.IoStateUnknown).Exec(ctx))
					} else {
						item := createItem(tx.Client())
						if dependency == "relocation-attempt" {
							tx.RelocationItem.UpdateOne(item).SetState(relocationitem.StateFailed).ExecX(ctx)
							tx.RelocationAttempt.Create().SetItemID(item.ID).SetFence(1).SetTargetKey("attempt").
								SetIoState(relocationattempt.IoStateEnded).SetCleanup(relocationattempt.CleanupPending).ExecX(ctx)
						}
					}
				}
				require.NoError(t, tx.Commit())
			}
			close(resume)
			require.ErrorIs(t, <-done, expected)
			require.Equal(t, types.PolicyTypeLocal, c.StoragePolicy.GetX(ctx, parent.ID).Type)
		})
	}
}

func TestPoolAssignmentsWithDisjointChildrenDoNotDeadlock(t *testing.T) {
	for _, mode := range []string{"new", "new-inherited", "existing-empty-inherited", "convert-inherited"} {
		t.Run(mode, func(t *testing.T) {
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if driver == "sqlite3" {
				t.Skip("SQLite serializes database writers")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			require.NoError(t, c.Schema.Create(ctx))
			var children []*ent.StoragePolicy
			for _, name := range []string{"A", "B"} {
				children = append(children, c.StoragePolicy.Create().SetName(name).SetType(types.PolicyTypeLocal).SaveX(ctx))
			}
			inputs := make([]*ent.StoragePolicy, len(children))
			for i, child := range children {
				inputs[i] = &ent.StoragePolicy{Name: "Pool " + child.Name, Type: types.PolicyTypeLoadBalance}
				if mode == "existing-empty-inherited" || mode == "convert-inherited" {
					kind := types.PolicyTypeLoadBalance
					if mode == "convert-inherited" {
						kind = types.PolicyTypeLocal
					}
					inputs[i] = c.StoragePolicy.Create().SetName(inputs[i].Name).SetType(kind).SaveX(ctx)
					inputs[i].Type = types.PolicyTypeLoadBalance
				}
				inputs[i].Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: child.ID, Weight: 1}}
			}
			ready, resume := make(chan struct{}, 2), make(chan struct{})
			c.Setting.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					if mutation.Op().Is(ent.OpCreate) {
						// Start both requests before the configuration fence. A
						// serialized writer cannot join a barrier inside it.
						ready <- struct{}{}
						select {
						case <-resume:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					return next.Mutate(ctx, mutation)
				})
			})
			done := make(chan error, 2)
			for _, input := range inputs {
				go func() {
					client := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
					writeCtx := ctx
					var tx *Tx
					var err error
					if mode != "new" {
						client, tx, writeCtx, err = WithTx(ctx, client)
						if err != nil {
							done <- err
							return
						}
						defer Rollback(tx)
					}
					_, err = client.Upsert(writeCtx, input)
					if err == nil && tx != nil {
						err = Commit(tx)
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
			require.Equal(t, 2, c.PolicyLoadBalance.Query().CountX(ctx))
			for i, input := range inputs {
				stored := c.StoragePolicy.Query().Where(storagepolicy.Name(input.Name)).OnlyX(ctx)
				require.Equal(t, types.PolicyTypeLoadBalance, stored.Type)
				member := stored.QueryPolicyLoadBalance().OnlyX(ctx)
				require.Equal(t, children[i].ID, member.StoragePolicyID)
			}
		})
	}
}

func TestShareCreationUsesCurrentCreatorInInheritedSnapshot(t *testing.T) {
	for _, active := range []bool{true, false} {
		t.Run(fmt.Sprintf("new-active=%t", active), func(t *testing.T) {
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if driver != "mysql" {
				t.Skip("MySQL repeatable-read unchanged creator checks")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			require.NoError(t, c.Schema.Create(ctx))
			g := c.Group.Create().SetName("Owners").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
			owner := c.User.Create().SetEmail("owner@example.com").SetNick("Owner").SetStatus(user.StatusActive).SetGroupID(g.ID).SaveX(ctx)
			file := c.File.Create().SetName("Shared folder").SetType(int(types.FileTypeFolder)).SetOwner(owner).SaveX(ctx)
			var creator *ent.User
			createCreator := func() {
				creator = c.User.Create().SetEmail("creator@example.com").SetNick("Creator").SetStatus(user.StatusActive).SetGroupID(g.ID).SaveX(ctx)
			}
			if !active {
				createCreator()
			}
			writer, tx, txCtx, err := WithTx(ctx, NewShareClient(c, "", nil))
			require.NoError(t, err)
			defer Rollback(tx)
			_, err = writer.GetClient().User.Query().All(txCtx)
			require.NoError(t, err)
			if active {
				createCreator()
			} else {
				c.User.UpdateOne(creator).SetStatus(user.StatusManualBanned).ExecX(ctx)
			}
			stamp := c.User.GetX(ctx, creator.ID).UpdatedAt
			c.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					m := mutation.(*ent.UserMutation)
					if added, ok := m.AddedStorage(); ok && added == 0 {
						m.SetUpdatedAt(stamp)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			link, err := writer.Upsert(txCtx, &CreateShareParams{OwnerID: creator.ID, FileID: file.ID})
			require.NoError(t, Commit(tx))
			if active {
				require.NoError(t, err)
				stored := c.Share.Query().WithUser().WithFile().OnlyX(ctx)
				require.Equal(t, link.ID, stored.ID)
				require.Equal(t, creator.ID, stored.Edges.User.ID)
				require.Equal(t, file.ID, stored.Edges.File.ID)
			} else {
				require.Error(t, err)
				require.Zero(t, c.Share.Query().CountX(ctx))
			}
		})
	}
}

func TestIndependentPoolReplacementsDoNotDeadlock(t *testing.T) {
	c, raw, driver, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	if driver == "sqlite3" {
		t.Skip("SQLite serializes database writers; InnoDB gap locks run in the database matrix")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.Schema.Create(ctx))
	var policies []*ent.StoragePolicy
	for id := 1; id <= 6; id++ {
		kind := types.PolicyTypeLocal
		if id == 2 || id == 6 {
			kind = types.PolicyTypeLoadBalance
		}
		policies = append(policies, c.StoragePolicy.Create().SetName(fmt.Sprint(id)).SetType(kind).SaveX(ctx))
	}
	for _, pair := range [][2]int{{2, 4}, {6, 1}} {
		c.PolicyLoadBalance.Create().SetLoadBalanceID(policies[pair[0]-1].ID).
			SetStoragePolicyID(policies[pair[1]-1].ID).SetWeight(1).ExecX(ctx)
	}
	ready, resume := make(chan struct{}, 2), make(chan struct{})
	c.Setting.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if mutation.Op().Is(ent.OpCreate) {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	done := make(chan error, 2)
	client := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
	for _, pair := range [][2]int{{2, 5}, {6, 3}} {
		input := *policies[pair[0]-1]
		input.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: policies[pair[1]-1].ID, Weight: 1}}
		go func() {
			_, err := client.Upsert(ctx, &input)
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
	for _, pair := range [][2]int{{2, 5}, {6, 3}} {
		member := policies[pair[0]-1].QueryPolicyLoadBalance().OnlyX(ctx)
		require.Equal(t, policies[pair[1]-1].ID, member.StoragePolicyID)
	}
}

func TestGroupOmittedPoliciesPreserveCurrentGrantsInInheritedSnapshot(t *testing.T) {
	for _, removePrevious := range []bool{false, true} {
		t.Run(fmt.Sprintf("previous-deleted=%t", removePrevious), func(t *testing.T) {
			testGroupOmittedPoliciesPreserveCurrentGrantsInInheritedSnapshot(t, removePrevious)
		})
	}
}

func TestPolicyDeletionSeesGrantsCommittedAfterInheritedSnapshot(t *testing.T) {
	for _, createGroupAfterSnapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("new-group=%t", createGroupAfterSnapshot), func(t *testing.T) {
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if driver != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			require.NoError(t, c.Schema.Create(ctx))
			p := c.StoragePolicy.Create().SetName("Destination").SetType(types.PolicyTypeLocal).SaveX(ctx)
			g := &ent.Group{Name: "Members", Permissions: &boolset.BooleanSet{}}
			if !createGroupAfterSnapshot {
				g = c.Group.Create().SetName(g.Name).SetPermissions(g.Permissions).SaveX(ctx)
			}
			policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
			writer, tx, txCtx, err := WithTx(ctx, policies)
			require.NoError(t, err)
			defer Rollback(tx)
			require.Zero(t, writer.GetClient().GroupPolicy.Query().CountX(txCtx))
			ids := []int{p.ID}
			g, err = NewGroupClient(c, "", nil).UpsertWithPolicies(ctx, g, &ids)
			require.NoError(t, err)
			require.ErrorIs(t, writer.Delete(txCtx, p), ErrStoragePolicyGranted)
			require.NoError(t, Commit(tx))
			require.NotNil(t, c.StoragePolicy.GetX(ctx, p.ID))
			require.Equal(t, p.ID, c.GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).OnlyX(ctx).StoragePolicyID)
		})
	}
}

func TestPolicyDeletionRejectsCompletedEntities(t *testing.T) {
	for _, afterSnapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("after-snapshot=%t", afterSnapshot), func(t *testing.T) {
			c, raw, driver, _ := migrationFixture(t)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })
			if afterSnapshot && driver == "sqlite3" {
				t.Skip("SQLite serializes database writers")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			require.NoError(t, c.Schema.Create(ctx))
			p := c.StoragePolicy.Create().SetName("Completed destination").SetType(types.PolicyTypeLocal).SaveX(ctx)
			createEntity := func() {
				c.Entity.Create().SetType(0).SetSource("completed").SetSize(1).SetStoragePolicyEntities(p.ID).ExecX(ctx)
			}
			if !afterSnapshot {
				createEntity()
			}
			client := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
			writer, tx, txCtx, err := WithTx(ctx, client)
			require.NoError(t, err)
			defer Rollback(tx)
			_, err = writer.GetClient().Entity.Query().Count(txCtx)
			require.NoError(t, err)
			if afterSnapshot {
				createEntity()
			}
			require.ErrorIs(t, writer.Delete(txCtx, p), ErrStoragePolicyInUse)
			require.NoError(t, Commit(tx))
			require.Nil(t, c.StoragePolicy.GetX(ctx, p.ID).DeletedAt)
			require.Equal(t, 1, c.Entity.Query().CountX(ctx))
		})
	}
}

func TestPolicyDeletionDoesNotInvertGroupLifecycleLocks(t *testing.T) {
	c, raw, driver, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	if driver == "sqlite3" {
		t.Skip("SQLite serializes database writers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	require.NoError(t, c.Schema.Create(ctx))
	p := c.StoragePolicy.Create().SetName("Destination").SetType(types.PolicyTypeLocal).SaveX(ctx)
	groups := NewGroupClient(c, "", nil)
	ids := []int{p.ID}
	g, err := groups.UpsertWithPolicies(ctx, &ent.Group{Name: "Members", Permissions: &boolset.BooleanSet{}}, &ids)
	require.NoError(t, err)
	type probe struct{}
	groupLocked, deleteReady := make(chan struct{}), make(chan struct{})
	c.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if marked, _ := ctx.Value(probe{}).(string); marked == "group" {
				// The writer holds the group row, before acquiring the policy.
				close(groupLocked)
				select {
				case <-deleteReady:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	c.GroupPolicy.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			if marked, _ := ctx.Value(probe{}).(string); marked == "delete" {
				// Deletion holds the policy row. Reading grants must not try
				// to acquire the group row in the opposite order.
				close(deleteReady)
			}
			return next.Query(ctx, query)
		})
	}))
	done := make(chan error, 1)
	go func() {
		_, err := groups.UpsertWithPolicies(context.WithValue(ctx, probe{}, "group"), g, &ids)
		done <- err
	}()
	select {
	case <-groupLocked:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
	require.ErrorIs(t, policies.Delete(context.WithValue(ctx, probe{}, "delete"), p), ErrStoragePolicyGranted)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Equal(t, 1, c.GroupPolicy.Query().CountX(ctx))
}

func TestGroupPolicyCreationWithDisjointPoliciesDoesNotDeadlock(t *testing.T) {
	for _, mode := range []string{"new", "new-inherited", "existing-unassigned", "existing-unassigned-inherited"} {
		t.Run(mode, func(t *testing.T) { testGroupPolicyCreationWithDisjointPoliciesDoesNotDeadlock(t, mode) })
	}
}

func TestGroupPolicyReplacementSeesGrantsCommittedAfterInheritedSnapshot(t *testing.T) {
	c, raw, driver, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	if driver != "mysql" {
		t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.Schema.Create(ctx))
	a := c.StoragePolicy.Create().SetName("Concurrent grant").SetType(types.PolicyTypeLocal).SaveX(ctx)
	b := c.StoragePolicy.Create().SetName("Replacement").SetType(types.PolicyTypeLocal).SaveX(ctx)
	g := c.Group.Create().SetName("Initially unassigned").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
	groups := NewGroupClient(c, "", nil)
	writer, tx, txCtx, err := WithTx(ctx, groups)
	require.NoError(t, err)
	defer Rollback(tx)
	require.Zero(t, writer.GetClient().GroupPolicy.Query().CountX(txCtx))
	ids := []int{a.ID}
	_, err = groups.UpsertWithPolicies(ctx, g, &ids)
	require.NoError(t, err)
	ids = []int{b.ID}
	_, err = writer.UpsertWithPolicies(txCtx, g, &ids)
	require.NoError(t, err)
	require.NoError(t, Commit(tx))
	grants := c.GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).AllX(ctx)
	require.Len(t, grants, 1)
	require.Equal(t, b.ID, grants[0].StoragePolicyID)
	require.Equal(t, b.ID, c.Group.GetX(ctx, g.ID).StoragePolicyID)
}

func testGroupPolicyCreationWithDisjointPoliciesDoesNotDeadlock(t *testing.T, mode string) {
	c, raw, driver, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	if driver == "sqlite3" {
		t.Skip("SQLite serializes database writers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, c.Schema.Create(ctx))
	var policies []*ent.StoragePolicy
	for _, name := range []string{"A", "B"} {
		policies = append(policies, c.StoragePolicy.Create().SetName(name).SetType(types.PolicyTypeLocal).SaveX(ctx))
	}
	var inputs []*ent.Group
	for _, p := range policies {
		input := &ent.Group{Name: p.Name, Permissions: &boolset.BooleanSet{}}
		if mode == "existing-unassigned" || mode == "existing-unassigned-inherited" {
			input = c.Group.Create().SetName(input.Name).SetPermissions(input.Permissions).SaveX(ctx)
		}
		inputs = append(inputs, input)
	}
	ready, resume := make(chan struct{}, 2), make(chan struct{})
	c.GroupPolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if mutation.Op().Is(ent.OpCreate) {
				// Both groups have finished any old-grant deletion before
				// either inserts into the previously empty grant index range.
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	done := make(chan error, 2)
	for i, p := range policies {
		go func() {
			client := NewGroupClient(c, "", nil)
			writeCtx := ctx
			var inherited *Tx
			var err error
			if mode == "new-inherited" || mode == "existing-unassigned-inherited" {
				client, inherited, writeCtx, err = WithTx(ctx, client)
				if err != nil {
					done <- err
					return
				}
				defer Rollback(inherited)
			}
			ids := []int{p.ID}
			_, err = client.UpsertWithPolicies(writeCtx, inputs[i], &ids)
			if err == nil && inherited != nil {
				err = Commit(inherited)
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
	require.Equal(t, 2, c.Group.Query().CountX(ctx))
	require.Equal(t, 2, c.GroupPolicy.Query().CountX(ctx))
}

func testGroupOmittedPoliciesPreserveCurrentGrantsInInheritedSnapshot(t *testing.T, removePrevious bool) {
	c, raw, driver, _ := migrationFixture(t)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	if driver != "mysql" {
		t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, c.Schema.Create(ctx))
	a := c.StoragePolicy.Create().SetName("Old default").SetType(types.PolicyTypeLocal).SaveX(ctx)
	b := c.StoragePolicy.Create().SetName("Current default").SetType(types.PolicyTypeLocal).SaveX(ctx)
	client := NewGroupClient(c, "", nil)
	ids := []int{a.ID}
	g, err := client.UpsertWithPolicies(ctx, &ent.Group{Name: "Members", Permissions: &boolset.BooleanSet{}}, &ids)
	require.NoError(t, err)
	writer, tx, txCtx, err := WithTx(ctx, client)
	require.NoError(t, err)
	defer Rollback(tx)
	require.Equal(t, 1, writer.GetClient().GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).CountX(txCtx))
	ids = []int{b.ID}
	_, err = client.UpsertWithPolicies(ctx, g, &ids)
	require.NoError(t, err)
	if removePrevious {
		policies := NewStoragePolicyClient(c, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
		require.NoError(t, policies.Delete(ctx, a))
	}
	_, err = writer.UpsertWithPolicies(txCtx, &ent.Group{ID: g.ID, Name: "Renamed", Permissions: g.Permissions}, nil)
	require.NoError(t, err)
	require.NoError(t, Commit(tx))
	current := c.Group.GetX(ctx, g.ID)
	require.Equal(t, "Renamed", current.Name)
	require.Equal(t, b.ID, current.StoragePolicyID, "an omitted list must not restore the snapshot's old default")
	grant := c.GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).OnlyX(ctx)
	require.Equal(t, b.ID, grant.StoragePolicyID)
}
