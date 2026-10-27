package controllers_test

import (
	"context"
	"encoding/json"
	entgo "entgo.io/ent"
	"errors"
	"fmt"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/share"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) setDefaultShares(t *testing.T, ids ...int) {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	if ids == nil {
		ids = []int{}
	}
	raw, _ := json.Marshal(ids)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": string(raw)}}, nil)
	f.login(t)
}
func (f *storageFixture) defaultShare(t *testing.T, name string) (int, string) {
	t.Helper()
	f.upload(t, "cloudreve://my/"+name+"/readme.txt", []byte("welcome"), nil)
	id, uri := f.createWritableShare(t, "cloudreve://my/"+name, map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	n, err := f.dep.HashIDEncoder().Decode(id, hashid.ShareID)
	require.NoError(t, err)
	return n, uri
}

func TestDefaultSharesConfigurationValidatesCurrentSourcesInInheritedTransaction(t *testing.T) {
	for _, mode := range []string{"revoked", "new-link"} {
		t.Run(mode, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite retains the accepting transaction's sole connection")
			}
			id, _ := f.defaultShare(t, "configuration-source")
			f.setDefaultShares(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			writer.GetClient().Share.Query().CountX(txCtx)
			if mode == "revoked" {
				require.NoError(t, f.dep.ShareClient().Delete(ctx, id))
			} else {
				id, _ = f.defaultShare(t, "new-configuration-source")
			}
			raw := fmt.Sprintf("[%d]", id)
			_, err = inventory.SaveDefaultShares(txCtx, writer.GetClient(), raw)
			if mode == "revoked" {
				require.Error(t, err, "a newly selected revoked link is not a retained configuration entry")
				require.NoError(t, inventory.Rollback(tx))
				return
			}
			require.NoError(t, err, "a newly committed valid link must remain selectable")
			require.NoError(t, inventory.Commit(tx))
		})
	}
}

func TestDefaultSharesConfigurationRetainsOnlyCurrentSelections(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained=%t", retained), func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite retains the accepting transaction's sole connection")
			}
			id, _ := f.defaultShare(t, "retained-configuration-source")
			if retained {
				f.setDefaultShares(t)
			} else {
				f.setDefaultShares(t, id)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			writer.GetClient().Setting.Query().CountX(txCtx)
			if retained {
				f.setDefaultShares(t, id)
			} else {
				f.setDefaultShares(t)
			}
			require.NoError(t, f.dep.ShareClient().Delete(ctx, id))
			raw := fmt.Sprintf("[%d]", id)
			_, err = inventory.SaveDefaultShares(txCtx, writer.GetClient(), raw)
			if !retained {
				require.Error(t, err, "a removed selection must be validated as new")
				require.NoError(t, inventory.Rollback(tx))
				return
			}
			require.NoError(t, err, "currently retained unavailable selections remain removable")
			require.NoError(t, inventory.Commit(tx))
			stored, err := f.dep.SettingClient().Get(ctx, inventory.DefaultSharesSetting)
			require.NoError(t, err)
			require.JSONEq(t, raw, stored)
		})
	}
}

func TestDefaultSharesConfigurationPreservesPendingSourcesAndCallerTransaction(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.defaultShare(t, "configuration-seed")
			f.setDefaultShares(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			root := writer.GetClient().File.Query().Where(file.OwnerID(2), file.Name(inventory.RootFolderName)).OnlyX(txCtx)
			source := writer.GetClient().File.Create().SetOwnerID(2).SetParent(root).SetType(int(types.FileTypeFolder)).SetName("pending-configuration-source").SaveX(txCtx)
			link, err := f.dep.ShareClient().Upsert(txCtx, &inventory.CreateShareParams{OwnerID: 2, FileID: source.ID})
			require.NoError(t, err)
			raw := fmt.Sprintf("[%d]", link.ID)
			_, err = inventory.SaveDefaultShares(txCtx, writer.GetClient(), raw)
			require.NoError(t, err)
			if commit {
				require.NoError(t, inventory.Commit(tx))
			} else {
				require.NoError(t, inventory.Rollback(tx))
				raw = "[]"
			}
			stored, err := f.dep.SettingClient().Get(ctx, inventory.DefaultSharesSetting)
			require.NoError(t, err)
			require.JSONEq(t, raw, stored)
			_, err = f.db.Share.Get(ctx, link.ID)
			if commit {
				require.NoError(t, err)
			} else {
				require.True(t, ent.IsNotFound(err), "configuration saves must not commit caller-owned sources")
			}
		})
	}
}

func TestDefaultSharesPendingSourceDoesNotInvertConfigurationLocks(t *testing.T) {
	for _, operation := range []string{"save", "install"} {
		t.Run(operation, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite serializes writes on its single connection")
			}
			id, _ := f.defaultShare(t, "configuration-lock-source")
			f.setDefaultShares(t, id)
			competingID := id
			if operation == "save" {
				competingID, _ = f.defaultShare(t, "competing-configuration-source")
			}
			visitor, _ := f.createWritableVisitor(t, 2)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			root := writer.GetClient().File.Query().Where(file.OwnerID(2), file.Name(inventory.RootFolderName)).OnlyX(txCtx)
			source := writer.GetClient().File.Create().SetOwnerID(2).SetParent(root).SetType(int(types.FileTypeFolder)).SetName("pending-lock-source").SaveX(txCtx)
			link, err := f.dep.ShareClient().Upsert(txCtx, &inventory.CreateShareParams{OwnerID: 2, FileID: source.ID})
			require.NoError(t, err)
			type competingRequest struct{}
			waiting := make(chan struct{})
			var paused atomic.Bool
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					if ctx.Value(competingRequest{}) == true && paused.CompareAndSwap(false, true) {
						close(waiting)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			finished := make(chan error, 1)
			go func() {
				otherCtx := context.WithValue(ctx, competingRequest{}, true)
				if operation == "install" {
					_, _, err := inventory.InstallDefaultShares(otherCtx, f.dep.UserClient(), visitor.ID, f.dep.HashIDEncoder(), true)
					finished <- err
					return
				}
				other, otherTx, otherCtx, err := inventory.WithTx(otherCtx, f.dep.UserClient())
				if err != nil {
					finished <- err
					return
				}
				defer inventory.Rollback(otherTx)
				_, err = inventory.SaveDefaultShares(otherCtx, other.GetClient(), fmt.Sprintf("[%d]", competingID))
				if err == nil {
					err = inventory.Commit(otherTx)
				}
				finished <- err
			}()
			awaitPermissionPause(t, waiting)
			_, saveErr := inventory.SaveDefaultShares(txCtx, writer.GetClient(), fmt.Sprintf("[%d]", link.ID))
			if saveErr == nil {
				saveErr = inventory.Commit(tx)
			} else {
				_ = inventory.Rollback(tx)
			}
			var otherErr error
			select {
			case otherErr = <-finished:
			case <-ctx.Done():
				otherErr = ctx.Err()
			}
			require.NoError(t, saveErr)
			require.NoError(t, otherErr)
		})
	}
}

func TestDefaultSharesPendingSourcesRequireCompleteOwnerFence(t *testing.T) {
	for _, prelocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("prelocked=%t", prelocked), func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite serializes writes on its single connection")
			}
			lower, _ := f.defaultShare(t, "lower-owner-source")
			higher, password := f.createWritableVisitor(t, 2)
			f.loginAs(t, higher.Email, password)
			higherLink, _ := f.defaultShare(t, "higher-owner-source")
			f.setDefaultShares(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			if prelocked {
				require.NoError(t, inventory.LockPermissionOwners(txCtx, writer.GetClient(), 2, higher.ID))
			}
			root := writer.GetClient().File.Query().Where(file.OwnerID(higher.ID), file.Name(inventory.RootFolderName)).OnlyX(txCtx)
			source := writer.GetClient().File.Create().SetOwnerID(higher.ID).SetParent(root).SetType(int(types.FileTypeFolder)).SetName("pending-higher-source").SaveX(txCtx)
			pending, err := f.dep.ShareClient().Upsert(txCtx, &inventory.CreateShareParams{OwnerID: higher.ID, FileID: source.ID})
			require.NoError(t, err)
			type competingRequest struct{}
			waiting := make(chan struct{})
			var attempts atomic.Int32
			barrier := int32(2)
			if prelocked {
				barrier = 1
			}
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					if ctx.Value(competingRequest{}) == true && attempts.Add(1) == barrier {
						close(waiting)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			finished := make(chan error, 1)
			go func() {
				other, otherTx, otherCtx, err := inventory.WithTx(context.WithValue(ctx, competingRequest{}, true), f.dep.UserClient())
				if err != nil {
					finished <- err
					return
				}
				defer inventory.Rollback(otherTx)
				_, err = inventory.SaveDefaultShares(otherCtx, other.GetClient(), fmt.Sprintf("[%d,%d]", lower, higherLink))
				if err == nil {
					err = inventory.Commit(otherTx)
				}
				finished <- err
			}()
			awaitPermissionPause(t, waiting)
			_, saveErr := inventory.SaveDefaultShares(txCtx, writer.GetClient(), fmt.Sprintf("[%d,%d]", lower, pending.ID))
			// A refused configuration save must leave the caller able to commit
			// its pending source independently, releasing the competing writer.
			commitErr := inventory.Commit(tx)
			var otherErr error
			select {
			case otherErr = <-finished:
			case <-ctx.Done():
				otherErr = ctx.Err()
			}
			require.NoError(t, commitErr)
			require.NoError(t, otherErr)
			if prelocked {
				require.NoError(t, saveErr)
			} else {
				var conflict serializer.AppError
				require.ErrorAs(t, saveErr, &conflict)
				require.EqualValues(t, serializer.CodeLockConflict, conflict.Code)
			}
			_, err = f.db.Share.Get(ctx, pending.ID)
			require.NoError(t, err)
		})
	}
}

func TestDefaultSharesConfigurationFenceRequiresCompleteOwnerUnion(t *testing.T) {
	for _, prelocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("prelocked=%t", prelocked), func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite serializes writes on its single connection")
			}
			lower, _ := f.defaultShare(t, "configuration-lower-source")
			higher, password := f.createWritableVisitor(t, 2)
			f.loginAs(t, higher.Email, password)
			higherLink, _ := f.defaultShare(t, "configuration-higher-source")
			f.setDefaultShares(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			if prelocked {
				require.NoError(t, inventory.LockPermissionOwners(txCtx, writer.GetClient(), 2, higher.ID))
			}
			_, err = inventory.SaveDefaultShares(txCtx, writer.GetClient(), fmt.Sprintf("[%d]", lower))
			require.NoError(t, err)
			type competingRequest struct{}
			waiting := make(chan struct{})
			var paused atomic.Bool
			pause := func(ctx context.Context) {
				if ctx.Value(competingRequest{}) == true && paused.CompareAndSwap(false, true) {
					close(waiting)
				}
			}
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					if prelocked {
						pause(ctx)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			f.db.Setting.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					if !prelocked {
						pause(ctx)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			finished := make(chan error, 1)
			go func() {
				other, otherTx, otherCtx, err := inventory.WithTx(context.WithValue(ctx, competingRequest{}, true), f.dep.UserClient())
				if err != nil {
					finished <- err
					return
				}
				defer inventory.Rollback(otherTx)
				_, err = inventory.SaveDefaultShares(otherCtx, other.GetClient(), fmt.Sprintf("[%d]", higherLink))
				if err == nil {
					err = inventory.Commit(otherTx)
				}
				finished <- err
			}()
			awaitPermissionPause(t, waiting)
			_, _, installErr := inventory.InstallDefaultShares(txCtx, writer, higher.ID, f.dep.HashIDEncoder(), true)
			commitErr := inventory.Commit(tx)
			var otherErr error
			select {
			case otherErr = <-finished:
			case <-ctx.Done():
				otherErr = ctx.Err()
			}
			require.NoError(t, commitErr)
			require.NoError(t, otherErr)
			if prelocked {
				require.NoError(t, installErr)
			} else {
				var conflict serializer.AppError
				require.ErrorAs(t, installErr, &conflict)
				require.EqualValues(t, serializer.CodeLockConflict, conflict.Code)
			}
		})
	}
}

func TestDefaultSharesBootstrapUsesCurrentStateInInheritedTransaction(t *testing.T) {
	for _, mode := range []string{"automatic", "explicit", "stale-settings"} {
		t.Run(mode, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite keeps the caller's sole connection; pending bootstrap is covered separately")
			}
			id, _ := f.defaultShare(t, "inherited-welcome")
			f.setDefaultShares(t, id)
			visitor, password := f.createWritableVisitor(t, 2)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			stale, err := writer.GetByID(txCtx, visitor.ID)
			require.NoError(t, err)
			require.False(t, stale.Settings.DefaultShares.Done)
			require.Zero(t, writer.GetClient().File.Query().Where(file.OwnerID(visitor.ID)).CountX(txCtx))
			f.loginAs(t, visitor.Email, password)
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, nil)
			root := f.db.File.Query().Where(file.OwnerID(visitor.ID), file.Not(file.HasParent())).OnlyX(ctx)
			fresh := f.db.User.GetX(ctx, visitor.ID)
			fresh.Settings.Language = "zh-CN"
			require.NoError(t, f.dep.UserClient().SaveSettings(ctx, fresh))
			language := "zh-CN"
			if mode == "stale-settings" {
				stale.Settings.Language = "de-DE"
				require.NoError(t, f.dep.UserClient().SaveSettings(txCtx, stale))
				language = "de-DE"
			} else {
				installed, result, err := inventory.InstallDefaultShares(txCtx, writer, visitor.ID, f.dep.HashIDEncoder(), mode == "explicit")
				require.NoError(t, err)
				require.NoError(t, inventory.Commit(tx))
				require.Equal(t, root.ID, installed.ID, "bootstrap must reuse the committed personal root")
				require.Zero(t, result.Added, "an installed shortcut must not be recreated")
			}
			if mode == "stale-settings" {
				require.NoError(t, inventory.Commit(tx))
			}
			require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.Not(file.HasParent())).CountX(ctx))
			require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(ctx))
			fresh = f.db.User.GetX(ctx, visitor.ID)
			require.True(t, fresh.Settings.DefaultShares.Done, "a stale settings form must preserve bootstrap completion")
			require.Equal(t, language, fresh.Settings.Language)
		})
	}
}

func TestDefaultSharesBootstrapPreservesCallerTransaction(t *testing.T) {
	for _, visibility := range []string{"pending", "committed"} {
		for _, finish := range []string{"commit", "rollback"} {
			t.Run(visibility+"/"+finish, func(t *testing.T) {
				f := newWritableShareFixture(t)
				if visibility == "committed" && f.database.Type == "sqlite" {
					t.Skip("SQLite keeps the caller's sole connection")
				}
				if visibility == "pending" {
					id, _ := f.defaultShare(t, "pending-welcome")
					f.setDefaultShares(t, id)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
				require.NoError(t, err)
				defer inventory.Rollback(tx)
				writer.GetClient().User.Query().CountX(txCtx)
				createCtx := txCtx
				if visibility == "committed" {
					id, _ := f.defaultShare(t, "snapshot-new-welcome")
					f.setDefaultShares(t, id)
					createCtx = ctx
				}
				account, err := f.dep.UserClient().Create(createCtx, &inventory.NewUserArgs{
					Email: "pending-default-shares@example.com", Nick: "Pending member", GroupID: 2, Status: entuser.StatusActive, SkipBootstrap: true,
				})
				require.NoError(t, err)
				root, result, err := inventory.InstallDefaultShares(txCtx, f.dep.UserClient(), account.ID, f.dep.HashIDEncoder(), false)
				require.NoError(t, err)
				require.Equal(t, 1, result.Added)
				require.Equal(t, account.ID, root.OwnerID)
				require.True(t, writer.GetClient().User.Query().Where(entuser.ID(account.ID), inventory.CurrentPermissionRead).OnlyX(txCtx).Settings.DefaultShares.Done)
				if finish == "commit" {
					require.NoError(t, inventory.Commit(tx))
					require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(account.ID), file.IsSymbolic(true)).CountX(ctx))
					require.True(t, f.db.User.GetX(ctx, account.ID).Settings.DefaultShares.Done)
				} else {
					require.NoError(t, inventory.Rollback(tx))
					if visibility == "pending" {
						require.Zero(t, f.db.User.Query().Where(entuser.ID(account.ID)).CountX(ctx))
					} else {
						require.False(t, f.db.User.GetX(ctx, account.ID).Settings.DefaultShares.Done)
					}
					require.Zero(t, f.db.File.Query().Where(file.OwnerID(account.ID)).CountX(ctx))
				}
			})
		}
	}
}

func TestDefaultSharesIndependentRootsDoNotHoldEmptyRanges(t *testing.T) {
	f := newWritableShareFixture(t)
	if f.database.Type == "sqlite" {
		t.Skip("SQLite serializes native writers")
	}
	first, _ := f.createWritableVisitor(t, 2)
	second, _ := f.createWritableVisitor(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ready, resume := make(chan struct{}, 2), make(chan struct{})
	defer close(resume)
	f.db.File.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			owner, exists := m.Field(file.FieldOwnerID)
			if m.Op().Is(entgo.OpCreate) && exists && (owner == first.ID || owner == second.ID) {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, m)
		})
	})
	results := make(chan error, 2)
	for _, id := range []int{first.ID, second.ID} {
		go func() {
			_, _, err := inventory.InstallDefaultShares(ctx, f.dep.UserClient(), id, f.dep.HashIDEncoder(), false)
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	// Both native root lookups have completed before either INSERT starts.
	resume <- struct{}{}
	resume <- struct{}{}
	for range 2 {
		require.NoError(t, <-results)
	}
	for _, id := range []int{first.ID, second.ID} {
		require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(id), file.Not(file.HasParent())).CountX(ctx))
	}
}

func TestDefaultSharesCurrentListSurvivesInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"committed", "pending"} {
		t.Run(mode, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if mode == "committed" && f.database.Type == "sqlite" {
				t.Skip("SQLite keeps the caller's sole connection")
			}
			a, _ := f.defaultShare(t, "current-list-a")
			b, _ := f.defaultShare(t, "current-list-b")
			visitor, _ := f.createWritableVisitor(t, 2)
			if mode == "pending" {
				f.setDefaultShares(t, a)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			writer.GetClient().Setting.Query().CountX(txCtx)
			expected := "current-list-a"
			if mode == "committed" {
				f.setDefaultShares(t, a)
			} else {
				// The composed configuration save and installation share one
				// complete source/recipient fence before the configuration lock.
				require.NoError(t, inventory.LockPermissionOwners(txCtx, writer.GetClient(), 2, visitor.ID))
				_, err = inventory.SaveDefaultShares(txCtx, writer.GetClient(), fmt.Sprintf("[%d]", b))
				require.NoError(t, err)
				expected = "current-list-b"
			}
			_, result, err := inventory.InstallDefaultShares(txCtx, f.dep.UserClient(), visitor.ID, f.dep.HashIDEncoder(), true)
			require.NoError(t, err)
			require.Equal(t, 1, result.Added)
			require.Equal(t, expected, result.Files[0].Name)
			require.NoError(t, inventory.Commit(tx))
			installed := f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).OnlyX(ctx)
			require.Equal(t, expected, installed.Name)
			require.False(t, f.db.User.GetX(ctx, visitor.ID).Settings.DefaultShares.Done, "explicit installation must preserve automatic eligibility")
		})
	}
}

func TestDefaultSharesPendingConfigurationDoesNotRequireObsoleteOwners(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			f := newWritableShareFixture(t)
			a, _ := f.defaultShare(t, "obsolete-owner-source")
			owner, password := f.createWritableVisitor(t, 2)
			f.loginAs(t, owner.Email, password)
			b, _ := f.defaultShare(t, "pending-owner-source")
			f.setDefaultShares(t, a)
			recipient, _ := f.createWritableVisitor(t, 2)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			writer.GetClient().Setting.Query().CountX(txCtx)
			require.NoError(t, inventory.LockPermissionOwners(txCtx, writer.GetClient(), owner.ID, recipient.ID))
			_, err = inventory.SaveDefaultShares(txCtx, writer.GetClient(), fmt.Sprintf("[%d]", b))
			require.NoError(t, err)
			_, result, err := inventory.InstallDefaultShares(txCtx, f.dep.UserClient(), recipient.ID, f.dep.HashIDEncoder(), true)
			require.NoError(t, err, "pending configuration needs only its current source and recipient owners")
			require.Equal(t, 1, result.Added)
			require.Equal(t, "pending-owner-source", result.Files[0].Name)
			if f.database.Type != "sqlite" {
				require.Zero(t, f.db.File.Query().Where(file.OwnerID(recipient.ID), file.IsSymbolic(true)).CountX(ctx))
			}
			if commit {
				require.NoError(t, inventory.Commit(tx))
				installed := f.db.File.Query().Where(file.OwnerID(recipient.ID), file.IsSymbolic(true)).OnlyX(ctx)
				require.Equal(t, "pending-owner-source", installed.Name)
			} else {
				require.NoError(t, inventory.Rollback(tx))
				require.Zero(t, f.db.File.Query().Where(file.OwnerID(recipient.ID), file.IsSymbolic(true)).CountX(ctx))
			}
			stored := ""
			for _, row := range f.db.Setting.Query().AllX(ctx) {
				if row.Name == inventory.DefaultSharesSetting {
					stored = row.Value
				}
			}
			expected := a
			if commit {
				expected = b
			}
			require.JSONEq(t, fmt.Sprintf("[%d]", expected), stored)
			require.False(t, f.db.User.GetX(ctx, recipient.ID).Settings.DefaultShares.Done)
		})
	}
}

func TestDefaultSharesLargeShortcutInventoryUsesBoundedQueries(t *testing.T) {
	f := newWritableShareFixture(t)
	if f.database.Type != "mysql" {
		t.Skip("MySQL/MariaDB prepared-statement parameter limit")
	}
	id, _ := f.defaultShare(t, "large-inventory-default")
	f.setDefaultShares(t, id)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := f.db.File.Query().Where(file.OwnerID(visitor.ID), file.Not(file.HasParent())).OnlyX(ctx)
	const count = 65536
	for offset := 1; offset < count; offset += 256 {
		var batch []*ent.FileCreate
		for i := offset; i < min(offset+256, count); i++ {
			batch = append(batch, f.db.File.Create().SetOwnerID(visitor.ID).SetParentID(root.ID).
				SetType(int(types.FileTypeFolder)).SetIsSymbolic(true).SetName(fmt.Sprintf("saved-%05d", i)))
		}
		_, err := f.db.File.CreateBulk(batch...).Save(ctx)
		require.NoError(t, err)
	}
	_, result, err := inventory.InstallDefaultShares(ctx, f.dep.UserClient(), visitor.ID, f.dep.HashIDEncoder(), true)
	require.NoError(t, err)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	require.Equal(t, count, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(ctx))
}

func TestDefaultSharesSettingsSaveSeesNewAccountInInheritedSnapshot(t *testing.T) {
	for _, change := range []string{"unchanged", "changed"} {
		for _, finish := range []string{"commit", "rollback"} {
			t.Run(change+"/"+finish, func(t *testing.T) {
				f := newWritableShareFixture(t)
				if f.database.Type != "mysql" {
					t.Skip("MySQL/MariaDB repeatable-read unchanged-row fallback")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.UserClient())
				require.NoError(t, err)
				defer inventory.Rollback(tx)
				writer.GetClient().User.Query().CountX(txCtx)
				created, err := f.dep.UserClient().Create(ctx, &inventory.NewUserArgs{
					Email: "snapshot-new-settings@example.com", Nick: "New settings", GroupID: 2, Status: entuser.StatusActive, SkipBootstrap: true,
				})
				require.NoError(t, err)
				f.db.User.Use(func(next entgo.Mutator) entgo.Mutator {
					return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
						m.(*ent.UserMutation).SetUpdatedAt(created.UpdatedAt)
						return next.Mutate(ctx, m)
					})
				})
				input := *created
				settings := *created.Settings
				input.Settings = &settings
				if change == "changed" {
					input.Settings.Language = "de-DE"
				}
				require.NoError(t, f.dep.UserClient().SaveSettings(txCtx, &input))
				if finish == "commit" {
					require.NoError(t, inventory.Commit(tx))
				} else {
					require.NoError(t, inventory.Rollback(tx))
				}
				persisted := f.db.User.GetX(ctx, created.ID)
				expected := created.Settings.Language
				if finish == "commit" {
					expected = input.Settings.Language
				}
				require.Equal(t, expected, persisted.Settings.Language)
				require.Equal(t, created.Settings.DefaultShares, persisted.Settings.DefaultShares)
			})
		}
	}
}

func TestDefaultSharesInitialSnapshotAndCurrentAddition(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "welcome-a")
	b, _ := f.defaultShare(t, "welcome-b")
	f.setDefaultShares(t, a, a)
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t, b)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	files := f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).WithMetadata().AllX(context.Background())
	require.Len(t, files, 1)
	require.Equal(t, "welcome-a", files[0].Name)
	require.Equal(t, 1, f.db.AuditLog.Query().Where(auditlog.Type(int(types.AuditMount)), auditlog.FileID(files[0].ID)).CountX(context.Background()))
	for _, meta := range files[0].Edges.Metadata {
		if meta.Name == "sys:shared_redirect" {
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(meta.Value), nil, &listing)
			require.Contains(t, listing.Parent.Path, "default_share_identity=")
		}
	}
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Added)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	fresh := f.db.User.GetX(context.Background(), visitor.ID)
	require.True(t, fresh.Settings.DefaultShares.Done)
	// A settings form loaded before materialization cannot reset completion.
	visitor.Settings.Language = "zh-CN"
	require.NoError(t, inventory.NewUserClient(f.db).SaveSettings(context.Background(), visitor))
	require.True(t, f.db.User.GetX(context.Background(), visitor.ID).Settings.DefaultShares.Done)

	f.login(t)
	f.setDefaultShares(t)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Zero(t, result.Existing)
	require.Zero(t, result.Skipped)
}

func TestDefaultSharesSettingsValidationAndAccess(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "settings")
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	for _, raw := range []string{"null", "{}", "[0]", "[-1]", "[1.5]", "[\"1\"]", "[999999999]", "[" + strings.Repeat("1,", 100) + "1]", "[" + strings.Repeat(" ", 8192) + "]"} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": raw}}), raw)
	}
	f.setDefaultShares(t, a, a)
	f.db.Share.DeleteOneID(a).ExecX(context.Background())
	f.setDefaultShares(t, a)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": "[]"}}))
}

func TestDefaultSharesSelfServicePrivacyAndRevocation(t *testing.T) {
	f := newWritableShareFixture(t)
	a, uri := f.defaultShare(t, "protected")
	visitor, password := f.createWritableVisitor(t, 2)
	// Keep automatic onboarding empty, then expose a current recommendation.
	f.setDefaultShares(t, a)
	f.loginAs(t, visitor.Email, password)
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", map[string]any{"ids": []int{a + 1}, "user_id": 1}, &result)
	require.Equal(t, 1, result.Added)
	f.login(t)
	f.db.Share.UpdateOneID(a).SetPassword("not-a-public-link").ExecX(context.Background())
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Skipped)
	require.Zero(t, result.Added)
	f.login(t)
	f.db.Share.UpdateOneID(a).SetPassword("").SetProps(&types.ShareProps{Permissions: &types.PermissionSetting{Everyone: types.ReadOnlyPermissions(), Anonymous: types.ReadOnlyPermissions()}}).ExecX(context.Background())
	f.request(t, http.MethodPost, fmt.Sprintf("/api/v4/share/%s", hashid.EncodeShareID(f.dep.HashIDEncoder(), a)), map[string]any{"uri": "cloudreve://my/protected", "permissions": map[string]string{"everyone": "AA==", "anonymous": "AA=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil))
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Skipped)
	require.Equal(t, 1, f.db.Share.Query().Where(share.ID(a)).CountX(context.Background()))
}

func TestDefaultSharesUserOrganizationAndOldAccounts(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "organize")
	visitor, password := f.createWritableVisitor(t, 2)
	// Existing installations without an eligibility marker never auto-provision.
	f.db.User.UpdateOneID(visitor.ID).SetSettings(&types.UserSetting{Language: "zh-CN"}).ExecX(context.Background())
	f.setDefaultShares(t, a)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Empty(t, listing.Files)
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Added)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": "cloudreve://my/organize", "new_name": "renamed"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/moved", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/renamed"}, "dst": "cloudreve://my/moved"}, nil)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/moved/renamed"}}, nil)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()), "login/list does not resurrect the shortcut")
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Added)
	require.Equal(t, "zh-CN", f.db.User.GetX(context.Background(), visitor.ID).Settings.Language)
	require.Nil(t, f.db.User.GetX(context.Background(), visitor.ID).Settings.DefaultShares)
}

func TestDefaultSharesNativeAccountCreation(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "onboarding")
	f.setDefaultShares(t, a)
	// The public registration API must capture the same snapshot as local inventory creation.
	email := "signup-" + storageRandom(t) + "@example.com"
	password := storageRandom(t)
	f.request(t, http.MethodPost, "/api/v4/user", map[string]any{"email": email, "password": password}, nil)
	f.loginAs(t, email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	adminEmail := "admin-created-" + storageRandom(t) + "@example.com"
	f.request(t, http.MethodPut, "/api/v4/admin/user", map[string]any{"user": map[string]any{"email": adminEmail, "nick": "New member", "status": "active", "group_users": 2}, "password": password}, nil)
	f.loginAs(t, adminEmail, password)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
}

func TestDefaultSharesConcurrentRequestsAndFailureRollback(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "atomic")
	f.setDefaultShares(t, a)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	// Fail the metadata write after a shortcut insert: neither may survive.
	var fail atomic.Bool
	f.db.Metadata.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if fail.Load() {
				return nil, errors.New("controlled shortcut failure")
			}
			return next.Mutate(ctx, m)
		})
	})
	fail.Store(true)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil))
	require.Zero(t, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
	fail.Store(false)
	first := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, "defaults-first")
	second := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, "defaults-second")
	automatic := f.permissionAsyncRequest(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, "defaults-automatic")
	require.Zero(t, awaitPermissionResult(t, first).Code)
	require.Zero(t, awaitPermissionResult(t, second).Code)
	require.Zero(t, awaitPermissionResult(t, automatic).Code)
	require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
}

func TestDefaultSharesConfigurationRemovalAtCommitBoundary(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "removed-current")
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t, a)
	f.loginAs(t, visitor.Email, password)
	reached, resume := pausePermissionFileRead(t, f, "removed-current", "paused-default-removal")
	pending := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, "paused-default-removal")
	awaitPermissionPause(t, reached)
	f.setDefaultShares(t)
	resume()
	require.Zero(t, awaitPermissionResult(t, pending).Code)
	require.Zero(t, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
}

func TestDefaultSharesNativeOIDCSignupSnapshot(t *testing.T) {
	r, d, p, _, _ := nativeFixture(t)
	// The identity provider protocol runs unchanged; no source links are required
	// to prove that JIT creates durable eligibility only once.
	changeProvider(t, d, func(registry *oidc.Registry) { registry.Providers[0].Config.DirectSignIn = true })
	p.email = "default-shares-jit@example.com"
	target, proof := prepareExternal(t, r, 3, false, "")
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	created, err := inventory.NewUserClient(d.db).GetByEmail(context.Background(), p.email)
	require.NoError(t, err)
	require.NotNil(t, created.Settings.DefaultShares)
	state, err := json.Marshal(created.Settings.DefaultShares)
	require.NoError(t, err)
	target, proof = prepareExternal(t, r, 3, false, "")
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	fresh, err := inventory.NewUserClient(d.db).GetByID(context.Background(), created.ID)
	require.NoError(t, err)
	unchanged, err := json.Marshal(fresh.Settings.DefaultShares)
	require.NoError(t, err)
	require.JSONEq(t, string(state), string(unchanged))
}

func TestDefaultSharesExistingAccountRestartsAndUserSettings(t *testing.T) {
	t.Setenv("CLOUDREVE_PERMISSION_FULL_ROUTER", "1")
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "restart")
	old, password := f.createWritableVisitor(t, 2)
	f.db.User.UpdateOneID(old.ID).SetSettings(&types.UserSetting{Language: "zh-CN"}).ExecX(context.Background())
	f.setDefaultShares(t, a)
	pending, pendingPassword := f.createWritableVisitor(t, 2)
	for i := 0; i < 2; i++ {
		worker := launchStorageWorker(t, f)
		f.remote = worker.ready(t)
		f.loginAs(t, old.Email, password)
		var listing explorer.ListResponse
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
		if i == 0 {
			require.Empty(t, listing.Files)
			var result inventory.DefaultShareResult
			f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
			require.Equal(t, 1, result.Added)
		} else {
			require.Len(t, listing.Files, 1)
		}
		f.loginAs(t, pending.Email, pendingPassword)
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
		require.Len(t, listing.Files, 1)
		worker.stop(t)
		f.remote = ""
	}
	require.Nil(t, f.db.User.GetX(context.Background(), old.ID).Settings.DefaultShares)
	require.Equal(t, "zh-CN", f.db.User.GetX(context.Background(), old.ID).Settings.Language)
}

func TestDefaultSharesPrivateNamesAndIdentityGuards(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/secret-source/readme.txt", []byte("private"), nil)
	var link string
	gate := storageRandom(t)[:8]
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/secret-source", "is_private": true, "password": gate, "permissions": map[string]string{"everyone": "IQ=="}}, &link)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	id, err := f.dep.HashIDEncoder().Decode(strings.Split(strings.TrimPrefix(parsed.Path, "/s/"), "/")[0], hashid.ShareID)
	require.NoError(t, err)
	f.setDefaultShares(t, id)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, "Shared resource", listing.Files[0].Name)
	require.NotContains(t, fmt.Sprint(listing.Files), gate)
	require.NotContains(t, fmt.Sprint(listing.Files), "secret-source")
	redirect := listing.Files[0].Metadata["sys:shared_redirect"]
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(redirect), nil), "native password gate remains")
	protected, err := url.Parse(redirect)
	require.NoError(t, err)
	protected.User = url.UserPassword(protected.User.Username(), gate)
	protected.Path = "/readme.txt"
	require.Equal(t, []byte("private"), f.readFile(t, protected.String()))
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Skipped)
	// A different share incarnation must fail even if it is otherwise public.
	f.db.Share.UpdateOneID(id).SetPassword("").ExecX(context.Background())
	target, err := url.Parse(redirect)
	require.NoError(t, err)
	query := target.Query()
	query.Set("default_share_identity", "old-incarnation")
	target.RawQuery = query.Encode()
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(target.String()), nil))
}

func TestDefaultSharesInactiveActivationRetainsSnapshot(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "activated")
	f.setDefaultShares(t, a)
	password := storageRandom(t)
	pending, err := inventory.NewUserClient(f.db).Create(context.Background(), &inventory.NewUserArgs{Email: "inactive-" + storageRandom(t) + "@example.com", PlainPassword: password, Status: entuser.StatusInactive, GroupID: 2, SkipBootstrap: true})
	require.NoError(t, err)
	_, _, err = inventory.InstallDefaultShares(context.Background(), inventory.NewUserClient(f.db), pending.ID, f.dep.HashIDEncoder(), false)
	require.NoError(t, err)
	require.False(t, f.db.User.GetX(context.Background(), pending.ID).Settings.DefaultShares.Done)
	require.Zero(t, f.db.File.Query().Where(file.OwnerID(pending.ID), file.IsSymbolic(true)).CountX(context.Background()))
	f.setDefaultShares(t)
	f.db.User.UpdateOneID(pending.ID).SetStatus(entuser.StatusActive).ExecX(context.Background())
	f.loginAs(t, pending.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, "activated", listing.Files[0].Name)
}

func TestDefaultSharesBootstrapKeepsAdministratorAndEmptyEligibility(t *testing.T) {
	db := openAuthenticationDatabase(t, "default-shares-bootstrap.db")
	ctx := context.Background()
	for _, name := range []string{"Administrators", "Members"} {
		_, err := db.Group.Create().SetName(name).SetPermissions(&boolset.BooleanSet{}).Save(ctx)
		require.NoError(t, err)
	}
	first, err := inventory.NewUserClient(db).Create(ctx, &inventory.NewUserArgs{Email: "bootstrap@example.com", GroupID: 2, Status: entuser.StatusActive})
	require.NoError(t, err)
	saved := db.User.GetX(ctx, first.ID)
	require.Equal(t, 1, saved.GroupUsers)
	require.NotNil(t, saved.Settings.DefaultShares)
	require.Empty(t, saved.Settings.DefaultShares.Shares)
}

func TestDefaultSharesSingleFileAndIndependentLinks(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/guide.txt", []byte("single file guide"), nil)
	first, _ := f.createWritableShare(t, "cloudreve://my/guide.txt", map[string]any{"everyone": "IQ=="})
	second, _ := f.createWritableShare(t, "cloudreve://my/guide.txt", map[string]any{"everyone": "IQ=="})
	a, err := f.dep.HashIDEncoder().Decode(first, hashid.ShareID)
	require.NoError(t, err)
	b, err := f.dep.HashIDEncoder().Decode(second, hashid.ShareID)
	require.NoError(t, err)
	f.setDefaultShares(t, a, b)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 2)
	for _, entry := range listing.Files {
		require.Equal(t, int(types.FileTypeFile), entry.Type)
		require.Equal(t, []byte("single file guide"), f.readFile(t, entry.Metadata["sys:shared_redirect"]))
	}
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 2, result.Existing)
	require.NotEqual(t, listing.Files[0].Name, listing.Files[1].Name)
}

func TestDefaultSharesSignupAuditFailureRollsBackAccount(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "signup-rollback")
	f.setDefaultShares(t, a)
	var fail atomic.Bool
	f.db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if fail.Load() {
				return nil, errors.New("controlled audit failure")
			}
			return next.Mutate(ctx, m)
		})
	})
	email := "rollback-" + storageRandom(t) + "@example.com"
	fail.Store(true)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/user", map[string]any{"email": email, "password": storageRandom(t)}))
	_, err := inventory.NewUserClient(f.db).GetByEmail(context.Background(), email)
	require.Error(t, err)
	fail.Store(false)
}

func TestDefaultSharesProtectedSingleFile(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/private.txt", []byte("protected single file"), nil)
	gate := storageRandom(t)[:8]
	var link string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/private.txt", "is_private": true, "password": gate, "permissions": map[string]string{"everyone": "IQ=="}}, &link)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	id, err := f.dep.HashIDEncoder().Decode(strings.Split(strings.TrimPrefix(parsed.Path, "/s/"), "/")[0], hashid.ShareID)
	require.NoError(t, err)
	f.setDefaultShares(t, id)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	redirect, err := url.Parse(listing.Files[0].Metadata["sys:shared_redirect"])
	require.NoError(t, err)
	require.NotEmpty(t, redirect.Query().Get("default_share_identity"))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(redirect.String()), nil))
	redirect.User = url.UserPassword(redirect.User.Username(), gate)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(redirect.String()), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, []byte("protected single file"), f.readFile(t, listing.Files[0].Path))
}

func TestDefaultSharesManualShortcutHostCase(t *testing.T) {
	f := newWritableShareFixture(t)
	id, redirect := f.defaultShare(t, "manual-host")
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t, id)
	f.loginAs(t, visitor.Email, password)
	parsed, err := url.Parse(redirect)
	require.NoError(t, err)
	parsed.Host = "ShArE"
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/saved-manually", "type": "folder", "metadata": map[string]string{"sys:shared_redirect": parsed.String()}}, nil)
	// The native parser accepts case-insensitive filesystem hosts.
	parsed.Path = "/readme.txt"
	require.Equal(t, []byte("welcome"), f.readFile(t, parsed.String()))
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
}

func TestDefaultSharesRepairInvalidConfiguration(t *testing.T) {
	f := newWritableShareFixture(t)
	id, _ := f.defaultShare(t, "repair-config")
	for _, key := range []string{"default_symbolics", "default_symbolics_identities"} {
		for _, replacement := range []string{"[]", fmt.Sprintf("[%d]", id)} {
			t.Run(key+replacement, func(t *testing.T) {
				f.setDefaultShares(t, id)
				require.NoError(t, f.db.Setting.Create().SetName(key).SetValue("null-invalid").OnConflictColumns("name").UpdateNewValues().Exec(context.Background()))
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
				// A malformed previous value must not let an invalid new ID bypass validation.
				require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": "[999999999]"}}))
				f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": replacement}}, nil)
				f.login(t)
				visitor, password := f.createWritableVisitor(t, 2)
				f.loginAs(t, visitor.Email, password)
				var listing explorer.ListResponse
				f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
				expected := 0
				if replacement != "[]" {
					expected = 1
				}
				require.Len(t, listing.Files, expected)
			})
		}
	}
	// Repair tolerates invalid stored JSON, never database read failures.
	var fail atomic.Bool
	readFailure := errors.New("controlled settings read failure")
	f.db.Setting.Intercept(entgo.InterceptFunc(func(next entgo.Querier) entgo.Querier {
		return entgo.QuerierFunc(func(ctx context.Context, q entgo.Query) (entgo.Value, error) {
			if fail.Load() {
				return nil, readFailure
			}
			return next.Query(ctx, q)
		})
	}))
	uc, tx, ctx, err := inventory.WithTx(context.Background(), inventory.NewUserClient(f.db))
	require.NoError(t, err)
	fail.Store(true)
	_, err = inventory.SaveDefaultShares(ctx, uc.GetClient(), "[]")
	require.ErrorIs(t, err, readFailure)
	fail.Store(false)
	require.NoError(t, inventory.Rollback(tx))
	raw, err := inventory.NewSettingClient(f.db, nil).Get(context.Background(), "default_symbolics")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("[%d]", id), raw)

}
