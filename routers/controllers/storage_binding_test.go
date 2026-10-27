package controllers_test

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageFolderBindingRevalidatesCurrentGrantInInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"direct-revoked", "direct-granted", "pool-child-revoked", "pool-child-granted", "new-pool-granted", "new-policy-granted", "owner-group-revoked", "owner-group-granted"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var pool *ent.StoragePolicy
			var created *ent.StoragePolicy
			if mode == "pool-child-revoked" || mode == "pool-child-granted" {
				pool = f.pool(t, 1, 0)
				pool.Edges.PolicyLoadBalance = pool.Edges.PolicyLoadBalance[:1]
				var err error
				pool, err = f.dep.StoragePolicyClient().Upsert(ctx, pool)
				require.NoError(t, err)
				f.assignPolicies(t, pool.ID)
			} else {
				f.assignPolicies(t, f.policies[0].ID)
			}
			uri, err := fs.NewUriFromString("cloudreve://my/bound")
			require.NoError(t, err)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri.String(), "type": "folder"}, nil)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, 1, writer.GetClient().GroupPolicy.Query().Where(grouppolicy.GroupID(2)).CountX(txCtx))
			owner := writer.GetClient().User.Query().Where(user.ID(2)).WithGroup().OnlyX(txCtx)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			folder, err := fm.Get(txCtx, uri)
			require.NoError(t, err)
			before := f.db.File.GetX(ctx, folder.ID()).StoragePolicyFiles
			if pool != nil {
				pool.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: f.policies[1].ID, Weight: 0}}
				_, err = f.dep.StoragePolicyClient().Upsert(ctx, pool)
				require.NoError(t, err)
			} else if mode == "new-pool-granted" {
				pool = f.pool(t, 1, 0)
				f.assignPolicies(t, pool.ID)
			} else if mode == "new-policy-granted" {
				input := *f.policies[1]
				input.ID, input.Name = 0, "Committed after the snapshot"
				created, err = f.dep.StoragePolicyClient().Upsert(ctx, &input)
				require.NoError(t, err)
				f.assignPolicies(t, created.ID)
				stamp := f.db.StoragePolicy.GetX(ctx, created.ID).UpdatedAt
				f.db.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						m := mutation.(*ent.StoragePolicyMutation)
						if id, ok := m.ID(); ok && id == created.ID {
							m.SetUpdatedAt(stamp)
						}
						return next.Mutate(ctx, mutation)
					})
				})
			} else if mode == "owner-group-revoked" || mode == "owner-group-granted" {
				group := f.db.Group.GetX(ctx, 1)
				ids := []int{f.policies[1].ID}
				_, err = f.dep.GroupClient().UpsertWithPolicies(ctx, group, &ids)
				require.NoError(t, err)
				f.db.User.UpdateOneID(owner.ID).SetGroupUsers(group.ID).ExecX(ctx)
			} else {
				f.assignPolicies(t, f.policies[1].ID)
			}
			target, allowed := f.policies[0].ID, false
			if mode == "direct-granted" || mode == "pool-child-granted" || mode == "new-pool-granted" || mode == "owner-group-granted" {
				target, allowed = f.policies[1].ID, true
			}
			if created != nil {
				target, allowed = created.ID, true
			}
			err = fm.BindPolicy(txCtx, uri, target)
			if allowed {
				require.NoError(t, err)
				before = target
			} else {
				var denied serializer.AppError
				require.ErrorAs(t, err, &denied)
				require.Equal(t, serializer.CodeGroupNotAllowed, denied.Code)
			}
			require.NoError(t, inventory.Commit(tx))
			require.Equal(t, before, f.db.File.GetX(ctx, folder.ID()).StoragePolicyFiles)
		})
	}
}

func TestStorageFolderBindingSeesNewFolderInInheritedSnapshot(t *testing.T) {
	for _, unchanged := range []bool{false, true} {
		t.Run(fmt.Sprintf("unchanged=%t", unchanged), func(t *testing.T) {
			f := newStorageFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read new folder")
			}
			f.assignPolicies(t, f.policies[0].ID)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			_, err = writer.GetClient().File.Query().Count(txCtx)
			require.NoError(t, err)
			uri, err := fs.NewUriFromString("cloudreve://my/new-bound")
			require.NoError(t, err)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri.String(), "type": "folder"}, nil)
			if unchanged {
				f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": uri.String(), "policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)}, nil)
			}
			owner := f.db.User.Query().Where(user.ID(2)).WithGroup().OnlyX(ctx)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			target, err := fm.Get(ctx, uri)
			require.NoError(t, err)
			stamp := f.db.File.GetX(ctx, target.ID()).UpdatedAt
			f.db.File.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					m := mutation.(*ent.FileMutation)
					if id, ok := m.ID(); ok && id == target.ID() {
						m.SetUpdatedAt(stamp)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			require.NoError(t, fm.BindPolicy(txCtx, uri, f.policies[0].ID))
			require.NoError(t, inventory.Commit(tx))
			require.Equal(t, f.policies[0].ID, f.db.File.GetX(ctx, target.ID()).StoragePolicyFiles)
		})
	}
}

func TestStorageFolderBindingRejectsBannedOwnerInInheritedSnapshot(t *testing.T) {
	f := newStorageFixture(t)
	if f.database.Type != "mysql" {
		t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
	}
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	uri, err := fs.NewUriFromString("cloudreve://my/bound")
	require.NoError(t, err)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri.String(), "type": "folder"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
	require.NoError(t, err)
	defer inventory.Rollback(tx)
	owner := writer.GetClient().User.Query().Where(user.ID(2)).WithGroup().OnlyX(txCtx)
	txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(f.dep, owner)
	defer fm.Recycle()
	folder, err := fm.Get(txCtx, uri)
	require.NoError(t, err)
	before := f.db.File.GetX(ctx, folder.ID()).StoragePolicyFiles
	f.db.User.UpdateOneID(owner.ID).SetStatus(user.StatusManualBanned).ExecX(ctx)
	require.ErrorIs(t, fm.BindPolicy(txCtx, uri, f.policies[1].ID), fs.ErrOwnerOnly)
	require.NoError(t, inventory.Commit(tx))
	require.Equal(t, before, f.db.File.GetX(ctx, folder.ID()).StoragePolicyFiles)
}

func TestStorageFolderBindingAcceptsUnchangedOwnerLock(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	uri := "cloudreve://my/bound"
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
	stamp := f.db.User.GetX(context.Background(), 2).UpdatedAt
	var locked atomic.Bool
	f.db.User.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			m := mutation.(*ent.UserMutation)
			if added, ok := m.AddedStorage(); ok && added == 0 {
				// MySQL reports zero changed rows for a matching lifecycle lock
				// when the timestamp also remains at its stored precision.
				m.SetUpdatedAt(stamp)
				locked.Store(true)
			}
			return next.Mutate(ctx, mutation)
		})
	})
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": uri, "policy_id": b}, nil)
	require.True(t, locked.Load())
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
	require.Equal(t, b, listing.StoragePolicy.ID)
}

func TestStorageFolderBindingChangesFutureWritesWithoutMovingExistingContent(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	old := []byte("file created before binding remains in A")
	f.upload(t, "cloudreve://my/bound/old.txt", old, nil)
	var before explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/bound/old.txt"), nil, &before)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/bound", "policy_id": b}, nil)
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(old), capacity.Used)
	require.Equal(t, old, f.readFile(t, "cloudreve://my/bound/old.txt"))
	var after explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/bound/old.txt"), nil, &after)
	require.Equal(t, before.ExtendedInfo.Entities, after.ExtendedInfo.Entities)
	session := f.upload(t, "cloudreve://my/bound/new.txt", []byte("automatic write into bound B"), nil)
	require.Equal(t, b, session.StoragePolicy.ID)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/bound"), nil, &listing)
	require.Equal(t, b, listing.StoragePolicy.ID)
	require.True(t, listing.Props.Capability.Enabled(21))
}

func TestStorageCopySeesSourcesCommittedAfterInheritedSnapshot(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read copy source")
	}
	for _, kind := range []string{"folder", "file", "tree", "added-child"} {
		for _, commit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/commit=%t", kind, commit), func(t *testing.T) {
				f := newWritableShareFixture(t)
				f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/destination", "type": "folder"}, nil)
				if kind == "added-child" {
					f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/source", "type": "folder"}, nil)
				}
				marker := f.db.Setting.Create().SetName("copy_caller_marker").SetValue("original").SaveX(ctx)
				writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
				require.NoError(t, err)
				defer inventory.Rollback(tx)
				_, err = writer.GetClient().File.Query().Count(txCtx)
				require.NoError(t, err)
				writer.GetClient().Setting.UpdateOneID(marker.ID).SetValue("pending").ExecX(txCtx)
				data := []byte("current copied content")
				source := "cloudreve://my/source"
				content := source + "/nested/file.txt"
				if kind == "folder" {
					f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": source, "type": "folder"}, nil)
				} else {
					if kind == "file" {
						source, content = source+".txt", source+".txt"
					}
					f.upload(t, content, data, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID))
				}
				if kind == "tree" {
					parent := f.db.File.Query().Where(entfile.Name("source"), entfile.OwnerID(2)).OnlyX(ctx)
					writer.GetClient().File.Create().SetName("pending-child").SetType(int(types.FileTypeFolder)).SetOwnerID(2).SetParentID(parent.ID).SetStoragePolicyFiles(f.policies[0].ID).SaveX(txCtx)
				}
				owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
				require.NoError(t, err)
				txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
				fm := manager.NewFileManager(f.dep, owner)
				defer fm.Recycle()
				src, err := fs.NewUriFromString(source)
				require.NoError(t, err)
				dst, err := fs.NewUriFromString("cloudreve://my/destination")
				require.NoError(t, err)
				require.NoError(t, fm.MoveOrCopy(txCtx, []*fs.URI{src}, dst, true))
				destination := f.db.File.Query().Where(entfile.Name("destination"), entfile.OwnerID(2)).OnlyX(ctx)
				require.Zero(t, f.db.File.Query().Where(entfile.FileChildren(destination.ID)).CountX(ctx), "copy must retain caller ownership")
				require.Equal(t, 1, writer.GetClient().File.Query().Where(entfile.FileChildren(destination.ID), inventory.CurrentPermissionRead).CountX(txCtx))
				if kind == "tree" || kind == "added-child" {
					require.Equal(t, 2, writer.GetClient().File.Query().Where(entfile.Name("file.txt"), inventory.CurrentPermissionRead).CountX(txCtx))
				}
				if kind == "tree" {
					require.Equal(t, 2, writer.GetClient().File.Query().Where(entfile.Name("pending-child"), inventory.CurrentPermissionRead).CountX(txCtx))
				}
				require.Equal(t, "original", f.db.Setting.GetX(ctx, marker.ID).Value)
				if commit {
					require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
					require.Equal(t, "pending", f.db.Setting.GetX(ctx, marker.ID).Value)
					if kind != "folder" {
						copied := "cloudreve://my/destination/source/nested/file.txt"
						if kind == "file" {
							copied = "cloudreve://my/destination/source.txt"
						}
						require.Equal(t, data, f.readFile(t, copied))
					}
				} else {
					require.NoError(t, inventory.Rollback(tx))
					require.Zero(t, f.db.File.Query().Where(entfile.FileChildren(destination.ID)).CountX(ctx))
					require.Equal(t, "original", f.db.Setting.GetX(ctx, marker.ID).Value)
				}
			})
		}
	}
}

func TestStorageCopySeesOwnerCommittedAfterInheritedSnapshot(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read unchanged owner update")
	}
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.assignPolicies(t, f.policies[0].ID)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			_, err = writer.GetClient().User.Query().Count(txCtx)
			require.NoError(t, err)
			owner, err := f.dep.UserClient().Create(ctx, &inventory.NewUserArgs{
				Email: "new-copy-owner@example.com", Nick: "New copy owner", GroupID: 2, Status: user.StatusActive,
			})
			require.NoError(t, err)
			owner, err = f.dep.UserClient().GetLoginUserByID(ctx, owner.ID)
			require.NoError(t, err)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			src, err := fs.NewUriFromString("cloudreve://my/source")
			require.NoError(t, err)
			dst, err := fs.NewUriFromString("cloudreve://my/destination")
			require.NoError(t, err)
			_, err = fm.Create(ctx, src, types.FileTypeFolder)
			require.NoError(t, err)
			destination, err := fm.Create(ctx, dst, types.FileTypeFolder)
			require.NoError(t, err)
			stamp := f.db.User.GetX(ctx, owner.ID).UpdatedAt
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					mutation.(*ent.UserMutation).SetUpdatedAt(stamp)
					return next.Mutate(ctx, mutation)
				})
			})
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			require.NoError(t, fm.MoveOrCopy(txCtx, []*fs.URI{src}, dst, true))
			require.Zero(t, f.db.File.Query().Where(entfile.FileChildren(destination.ID())).CountX(ctx))
			require.Equal(t, 1, writer.GetClient().File.Query().Where(entfile.FileChildren(destination.ID()), inventory.CurrentPermissionRead).CountX(txCtx))
			if commit {
				require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
				require.Equal(t, 1, f.db.File.Query().Where(entfile.FileChildren(destination.ID())).CountX(ctx))
			} else {
				require.NoError(t, inventory.Rollback(tx))
				require.Zero(t, f.db.File.Query().Where(entfile.FileChildren(destination.ID())).CountX(ctx))
			}
		})
	}
}

func TestStorageCopyPreservesRetiredFolderPreferences(t *testing.T) {
	f := newWritableShareFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/source/nested", "type": "folder"}, nil)
	f.bindFolder(t, "cloudreve://my/source/nested", 1)
	current := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	data := []byte("copy preserves nested content with a retired preference")
	f.upload(t, "cloudreve://my/source/nested/original.txt", data, current)
	f.assignPolicies(t, f.policies[0].ID)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID), nil, nil)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/destination", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source"}, "dst": "cloudreve://my/destination", "copy": true}, nil)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/source/nested/original.txt"))
	require.Equal(t, data, f.readFile(t, "cloudreve://my/destination/source/nested/original.txt"))
	session := f.upload(t, "cloudreve://my/destination/source/nested/new.txt", []byte("future write uses current grant"), nil)
	require.Equal(t, current, session.StoragePolicy.ID)
}

func TestStorageCopyLimitUsesTheEffectiveInheritedScope(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read copy scope")
	}
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending=%t", pending), func(t *testing.T) {
			f := newWritableShareFixture(t)
			data := []byte("effective source fits the native limit")
			f.upload(t, "cloudreve://my/source/file.txt", data, nil)
			for _, uri := range []string{"cloudreve://my/source/old-a", "cloudreve://my/source/old-b", "cloudreve://my/source/old-c", "cloudreve://my/removed", "cloudreve://my/destination"} {
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			settings := *f.db.Group.GetX(ctx, 2).Settings
			settings.MaxWalkedFiles = 4
			f.db.Group.UpdateOneID(2).SetSettings(&settings).ExecX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Greater(t, writer.GetClient().File.Query().CountX(txCtx), 5)
			if pending {
				removed := f.db.File.Query().Where(entfile.Name("removed")).OnlyX(ctx)
				writer.GetClient().File.Update().Where(entfile.NameIn("old-a", "old-b", "old-c")).SetFileChildren(removed.ID).SaveX(txCtx)
			} else {
				f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source/old-a", "cloudreve://my/source/old-b", "cloudreve://my/source/old-c"}, "dst": "cloudreve://my/removed"}, nil)
			}
			owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			source, err := fs.NewUriFromString("cloudreve://my/source")
			require.NoError(t, err)
			destination, err := fs.NewUriFromString("cloudreve://my/destination")
			require.NoError(t, err)
			require.NoError(t, fm.MoveOrCopy(txCtx, []*fs.URI{source}, destination, true))
			require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
			f.login(t)
			require.Equal(t, data, f.readFile(t, "cloudreve://my/destination/source/file.txt"))
			require.Equal(t, 1, f.db.File.Query().Where(entfile.Name("old-a")).CountX(ctx))
		})
	}
}

func TestStorageCopyLimitDoesNotLeavePendingWritesInInheritedTransaction(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL inherited copy scope")
	}
	f := newWritableShareFixture(t)
	data := []byte("rejected copy leaves no partial subtree")
	f.upload(t, "cloudreve://my/source/nested/file.txt", data, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/destination", "type": "folder"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	settings := *f.db.Group.GetX(ctx, 2).Settings
	settings.MaxWalkedFiles = 2
	f.db.Group.UpdateOneID(2).SetSettings(&settings).ExecX(ctx)
	owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
	require.NoError(t, err)
	destination := f.db.File.Query().Where(entfile.Name("destination")).OnlyX(ctx)
	before := f.db.User.GetX(ctx, 2).Storage
	marker := f.db.Setting.Create().SetName("rejected_copy_caller_marker").SetValue("original").SaveX(ctx)
	writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
	require.NoError(t, err)
	defer inventory.Rollback(tx)
	writer.GetClient().Setting.UpdateOneID(marker.ID).SetValue("pending").ExecX(txCtx)
	txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(f.dep, owner)
	defer fm.Recycle()
	sourceURI, err := fs.NewUriFromString("cloudreve://my/source")
	require.NoError(t, err)
	destinationURI, err := fs.NewUriFromString("cloudreve://my/destination")
	require.NoError(t, err)
	require.Error(t, fm.MoveOrCopy(txCtx, []*fs.URI{sourceURI}, destinationURI, true))
	require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
	require.Equal(t, "pending", f.db.Setting.GetX(ctx, marker.ID).Value, "caller retains transaction ownership")
	require.Zero(t, f.db.File.Query().Where(entfile.FileChildren(destination.ID)).CountX(ctx))
	require.Equal(t, before, f.db.User.GetX(ctx, 2).Storage)
	f.login(t)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/source/nested/file.txt"))
}

func TestStorageRecursiveQuotaRejectionPreservesInheritedTransaction(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL inherited recursive quota rejection")
	}
	for _, operation := range []string{"copy", "cross-owner-move"} {
		for _, earlierBytes := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/earlier-bytes=%t", operation, earlierBytes), func(t *testing.T) {
				f := newWritableShareFixture(t)
				data := bytes.Repeat([]byte("q"), 20)
				f.upload(t, "cloudreve://my/source/nested/late.txt", data, nil)
				if earlierBytes {
					f.upload(t, "cloudreve://my/source/early.txt", data, nil)
				}
				destinationURI := "cloudreve://my/destination"
				receivingOwner := 2
				if operation == "cross-owner-move" {
					visitor, password := f.createWritableVisitor(t, 2)
					receivingOwner = visitor.ID
					f.loginAs(t, visitor.Email, password)
				}
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": destinationURI, "type": "folder"}, nil)
				if operation == "cross-owner-move" {
					_, destinationURI = f.createWritableShare(t, destinationURI, map[string]any{"everyone": "Pw=="})
					f.login(t)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				beforeStorage := f.db.User.GetX(ctx, receivingOwner).Storage
				group := f.db.Group.GetX(ctx, 2)
				group.MaxStorage = beforeStorage + 10
				if earlierBytes {
					group.MaxStorage += 15 // The early file fits; the nested file does not.
				}
				_, err := f.dep.GroupClient().UpsertWithPolicies(ctx, group, nil)
				require.NoError(t, err)
				owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
				require.NoError(t, err)
				ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
				fm := manager.NewFileManager(f.dep, owner)
				defer fm.Recycle()
				src, err := fs.NewUriFromString("cloudreve://my/source")
				require.NoError(t, err)
				dst, err := fs.NewUriFromString(destinationURI)
				require.NoError(t, err)
				beforeFiles := f.db.File.Query().CountX(ctx)
				entities := f.db.Entity.Query().AllX(ctx)
				beforeSourceStorage := f.db.User.GetX(ctx, 2).Storage
				marker := f.db.Setting.Create().SetName("quota_rejection_caller_marker").SetValue("original").SaveX(ctx)
				writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
				require.NoError(t, err)
				defer inventory.Rollback(tx)
				writer.GetClient().Setting.UpdateOneID(marker.ID).SetValue("pending").ExecX(txCtx)
				require.ErrorIs(t, fm.MoveOrCopy(txCtx, []*fs.URI{src}, dst, operation == "copy"), fs.ErrInsufficientCapacity)
				require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
				require.Equal(t, "pending", f.db.Setting.GetX(ctx, marker.ID).Value)
				require.Equal(t, beforeStorage, f.db.User.GetX(ctx, receivingOwner).Storage)
				require.Equal(t, beforeSourceStorage, f.db.User.GetX(ctx, 2).Storage)
				require.Equal(t, beforeFiles, f.db.File.Query().CountX(ctx), "rejected copy leaves no destination subtree")
				require.Equal(t, len(entities), f.db.Entity.Query().CountX(ctx))
				for _, entity := range entities {
					require.Equal(t, entity.ReferenceCount, f.db.Entity.GetX(ctx, entity.ID).ReferenceCount)
				}
				require.Equal(t, data, f.readFile(t, "cloudreve://my/source/nested/late.txt"))
				if earlierBytes {
					require.Equal(t, data, f.readFile(t, "cloudreve://my/source/early.txt"))
				}
				// Retrying at the exact full-tree budget succeeds with cached navigation.
				group.MaxStorage = beforeStorage + beforeSourceStorage
				_, err = f.dep.GroupClient().UpsertWithPolicies(ctx, group, nil)
				require.NoError(t, err)
				require.NoError(t, fm.MoveOrCopy(ctx, []*fs.URI{src}, dst, operation == "copy"))
				require.Equal(t, beforeStorage+beforeSourceStorage, f.db.User.GetX(ctx, receivingOwner).Storage)
				require.Equal(t, data, f.readFile(t, dst.Join("source/nested/late.txt").String()))
				if earlierBytes {
					require.Equal(t, data, f.readFile(t, dst.Join("source/early.txt").String()))
				}
				if operation == "cross-owner-move" {
					require.Zero(t, f.db.User.GetX(ctx, 2).Storage)
				}
			})
		}
	}
}

func TestStorageCopyReferencesIncludeMixedSnapshotDirectoryClosure(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read directory closure")
	}
	f := newWritableShareFixture(t)
	first, second := []byte("shared earlier entity"), []byte("shared later entity")
	f.upload(t, "cloudreve://my/seed.txt", first, nil)
	f.upload(t, "cloudreve://my/source/later.txt", second, nil)
	for _, uri := range []string{"cloudreve://my/bridge", "cloudreve://my/destination"} {
		f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := f.db.File.Query().Where(entfile.Name("source")).OnlyX(ctx)
	bridge := f.db.File.Query().Where(entfile.Name("bridge")).OnlyX(ctx)
	destination := f.db.File.Query().Where(entfile.Name("destination")).OnlyX(ctx)
	seed := f.db.File.Query().Where(entfile.Name("seed.txt")).OnlyX(ctx)
	owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
	require.NoError(t, err)
	writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
	require.NoError(t, err)
	defer inventory.Rollback(tx)
	writer.GetClient().File.Query().CountX(txCtx)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/seed.txt"}, "dst": "cloudreve://my/bridge", "copy": true}, nil)
	require.NoError(t, inventory.LockPermissionOwners(txCtx, writer.GetClient(), 2))
	writer.GetClient().File.UpdateOne(bridge).SetFileChildren(root.ID).ExecX(txCtx)
	require.NoError(t, inventory.LockCopyTreeReferences(txCtx, writer.GetClient(), []*ent.File{root}, destination.ID))
	probeCtx, probeCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	err = f.db.Entity.UpdateOneID(seed.PrimaryEntity).AddReferenceCount(0).Exec(probeCtx)
	probeCancel()
	require.ErrorIs(t, err, context.DeadlineExceeded, "the complete early fence must already hold the newly reachable first entity")
	txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(f.dep, owner)
	defer fm.Recycle()
	src, err := fs.NewUriFromString("cloudreve://my/source")
	require.NoError(t, err)
	dst, err := fs.NewUriFromString("cloudreve://my/destination")
	require.NoError(t, err)
	require.NoError(t, fm.MoveOrCopy(txCtx, []*fs.URI{src}, dst, true))
	require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
	require.Equal(t, first, f.readFile(t, "cloudreve://my/destination/source/bridge/seed.txt"))
	require.Equal(t, second, f.readFile(t, "cloudreve://my/destination/source/later.txt"))
}

func TestStorageShareCreationSeesSourceCommittedAfterInheritedSnapshot(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read share source metadata")
	}
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.ShareClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			writer.GetClient().File.Query().CountX(txCtx)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/new-share-source", "type": "folder"}, nil)
			source := f.db.File.Query().Where(entfile.Name("new-share-source")).OnlyX(ctx)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			created, err := writer.Upsert(txCtx, &inventory.CreateShareParams{OwnerID: owner.ID, FileID: source.ID})
			require.NoError(t, err)
			require.Zero(t, f.db.Share.Query().CountX(ctx))
			if commit {
				require.NoError(t, inventory.Commit(tx))
				require.Equal(t, source.ID, f.db.Share.GetX(ctx, created.ID).QueryFile().OnlyX(ctx).ID)
			} else {
				require.NoError(t, inventory.Rollback(tx))
				require.Zero(t, f.db.Share.Query().CountX(ctx))
			}
		})
	}
}

func TestStorageShareCreationInheritsPendingSource(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
			root := f.db.File.Query().Where(entfile.OwnerID(owner.ID), entfile.Name(inventory.RootFolderName)).OnlyX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			source, err := writer.CreateFolder(txCtx, root, &inventory.CreateFolderParameters{Owner: owner.ID, Name: "pending-share-source"})
			require.NoError(t, err)
			shareCtx, stop := context.WithTimeout(txCtx, 2*time.Second)
			defer stop()
			created, err := f.dep.ShareClient().Upsert(shareCtx, &inventory.CreateShareParams{OwnerID: owner.ID, FileID: source.ID})
			require.NoError(t, err)
			require.Equal(t, 1, writer.GetClient().Share.Query().CountX(txCtx))
			if os.Getenv("OIDC_TEST_DRIVER") != "" {
				require.Zero(t, f.db.Share.Query().CountX(ctx), "share admission must not commit the caller transaction")
			}
			if commit {
				require.NoError(t, inventory.Commit(tx))
				require.Equal(t, source.ID, f.db.Share.GetX(ctx, created.ID).QueryFile().OnlyX(ctx).ID)
			} else {
				require.NoError(t, inventory.Rollback(tx))
				require.Zero(t, f.db.Share.Query().CountX(ctx))
				require.False(t, f.db.File.Query().Where(entfile.ID(source.ID)).ExistX(ctx))
			}
		})
	}
}

func TestStorageCopyIgnoresRetirementOfObsoleteSnapshotAliases(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read obsolete physical aliases")
	}
	f := newWritableShareFixture(t)
	for _, uri := range []string{"cloudreve://my/source", "cloudreve://my/garbage", "cloudreve://my/destination"} {
		f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
	require.NoError(t, err)
	owner.Settings.VersionRetention = false
	require.NoError(t, f.dep.UserClient().SaveSettings(ctx, owner))
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(f.dep, owner)
	defer fm.Recycle()
	_, err = f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String("obsolete-alias"), Body: bytes.NewReader([]byte("old imported data"))})
	require.NoError(t, err)
	objects, err := fm.ListPhysical(ctx, "/", f.policies[0].ID, false, func(int) {})
	require.NoError(t, err)
	require.Len(t, objects, 1)
	for _, target := range []struct{ directory, name string }{{"source", "file.txt"}, {"garbage", "alias.txt"}} {
		destination, err := fs.NewUriFromString("cloudreve://my/" + target.directory)
		require.NoError(t, err)
		object := objects[0]
		object.RelativePath = target.name
		require.NoError(t, fm.ImportPhysical(ctx, destination, f.policies[0].ID, object, false))
	}
	source := f.db.File.Query().Where(entfile.Name("file.txt")).OnlyX(ctx)
	alias := f.db.File.Query().Where(entfile.Name("alias.txt")).OnlyX(ctx)
	writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
	require.NoError(t, err)
	defer inventory.Rollback(tx)
	require.Equal(t, source.PrimaryEntity, writer.GetClient().File.GetX(txCtx, source.ID).PrimaryEntity)
	data := []byte("current content survives retirement of the old alias")
	var session explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/source/file.txt", "size": len(data), "entity_type": "version"}, &session)
	f.finishUpload(t, session, data)
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/garbage/alias.txt"}, "skip_soft_delete": true}, nil)
	require.NoError(t, fm.RecycleEntities(ctx, false, alias.PrimaryEntity))
	require.Zero(t, f.db.Entity.GetX(ctx, source.PrimaryEntity).ReferenceCount)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/source/file.txt"))
	src, err := fs.NewUriFromString("cloudreve://my/source/file.txt")
	require.NoError(t, err)
	dst, err := fs.NewUriFromString("cloudreve://my/destination")
	require.NoError(t, err)
	require.NoError(t, fm.MoveOrCopy(txCtx, []*fs.URI{src}, dst, true))
	require.NoError(t, inventory.CommitWithStorageDiff(txCtx, tx, f.dep.Logger(), f.dep.UserClient()))
	require.Equal(t, data, f.readFile(t, "cloudreve://my/destination/file.txt"))
}

func TestStorageFolderBindingRejectsUnsupportedTargetsAndMissingPolicy(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.upload(t, "cloudreve://my/bound/file.txt", []byte("existing"), nil)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	for _, policy := range []any{nil, ""} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/bound", "policy_id": policy}))
	}
	require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/bound"}))
	foreign := hashid.EncodeUserID(f.dep.HashIDEncoder(), 1)
	for _, uri := range []string{"cloudreve://my/", "cloudreve://my/bound/file.txt", "cloudreve://trash/bound", "cloudreve://share/unknown", "cloudreve://" + foreign + "@my/bound", "cloudreve://my/missing"} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": uri, "policy_id": b}))
	}
	session := f.upload(t, "cloudreve://my/bound/after-reject.txt", []byte("failed bind preserved automatic A"), nil)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), session.StoragePolicy.ID)
}
