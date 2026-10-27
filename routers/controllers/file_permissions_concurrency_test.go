package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/stretchr/testify/require"
)

type permissionHTTPResult struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Error string `json:"error"`
}

func (f *storageFixture) permissionAsyncRequest(t *testing.T, method, path string, body any, agent string) <-chan permissionHTTPResult {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	token := f.token
	result := make(chan permissionHTTPResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		req := httptest.NewRequest(method, path, bytes.NewReader(raw)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", agent)
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, req)
		response := permissionHTTPResult{Code: -1}
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		result <- response
	}()
	return result
}
func pausePermissionFileRead(t *testing.T, f *storageFixture, name, agent string) (<-chan struct{}, func()) {
	t.Helper()
	reached, release := make(chan struct{}), make(chan struct{})
	var triggered atomic.Bool
	var released atomic.Bool
	resume := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(resume)
	f.db.File.Intercept(entgo.InterceptFunc(func(next entgo.Querier) entgo.Querier {
		return entgo.QuerierFunc(func(ctx context.Context, q entgo.Query) (entgo.Value, error) {
			value, err := next.Query(ctx, q)
			info := requestinfo.RequestInfoFromContext(ctx)
			if err == nil && info != nil && info.UserAgent == agent {
				if files, ok := value.([]*ent.File); ok {
					for _, file := range files {
						if file.Name == name && triggered.CompareAndSwap(false, true) {
							close(reached)
							select {
							case <-release:
							case <-ctx.Done():
								return nil, ctx.Err()
							}
							break
						}
					}
				}
			}
			return value, err
		})
	}))
	return reached, resume
}
func awaitPermissionPause(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("native request did not reach controlled read")
	}
}
func awaitPermissionResult(t *testing.T, ch <-chan permissionHTTPResult) permissionHTTPResult {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(20 * time.Second):
		t.Fatal("native request did not complete")
		return permissionHTTPResult{Code: -1}
	}
}
func TestFilePermissionsTransferRejectsStaleSetter(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/source/a.txt", []byte("transferred bytes"), nil)
	f.upload(t, "cloudreve://my/untouched.txt", []byte("untouched"), nil)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	f.upload(t, "cloudreve://my/receiver/seed.txt", []byte("seed"), nil)
	_, dst := f.createWritableShare(t, "cloudreve://my/receiver", map[string]any{"everyone": "Pw==", "anonymous": "IQ=="})
	f.login(t)
	reached, resume := pausePermissionFileRead(t, f, "a.txt", "paused-acl-transfer")
	result := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/source/a.txt", "cloudreve://my/untouched.txt"}, "setting": map[string]string{"everyone": "AA=="}}, "paused-acl-transfer")
	awaitPermissionPause(t, reached)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source/a.txt"}, "dst": dst, "copy": false}, nil)
	resume()
	require.NotZero(t, awaitPermissionResult(t, result).Code)
	require.Nil(t, f.permissionInfo(t, "cloudreve://my/untouched.txt").ExtendedInfo.Permissions)
	f.loginAs(t, visitor.Email, password)
	require.Nil(t, f.permissionInfo(t, "cloudreve://my/receiver/a.txt").ExtendedInfo.Permissions)
	require.Equal(t, []byte("transferred bytes"), f.readFile(t, "cloudreve://my/receiver/a.txt"))
}
func TestFilePermissionsConcurrentViewPreservesCurrentACL(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/props/item.txt", []byte("properties"), nil)
	reached, resume := pausePermissionFileRead(t, f, "props", "paused-view-acl")
	result := f.permissionAsyncRequest(t, http.MethodPatch, "/api/v4/file/view", map[string]any{"uri": "cloudreve://my/props", "view": map[string]any{"view": "list", "page_size": 50, "order_direction": "asc", "gallery_width": 200}}, "paused-view-acl")
	awaitPermissionPause(t, reached)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/props"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	resume()
	require.Zero(t, awaitPermissionResult(t, result).Code)
	info := f.permissionInfo(t, "cloudreve://my/props")
	require.Equal(t, []byte{0}, []byte(*info.ExtendedInfo.Permissions.Everyone))
	require.Equal(t, "list", info.ExtendedInfo.View.View)
}

func TestFilePermissionsInheritedViewPreservesCurrentACL(t *testing.T) {
	for _, clear := range []bool{false, true} {
		name := "set"
		if clear {
			name = "clear"
		}
		t.Run(name, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type != "mysql" && f.database.Type != "postgres" {
				t.Skip("SQLite serializes the independent permission writer")
			}
			const folder = "cloudreve://my/inherited-view"
			f.upload(t, folder+"/file.txt", []byte("retained view content"), nil)
			f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
				"uris": []string{folder}, "setting": map[string]string{"everyone": "IQ=="},
			}, nil)
			f.request(t, http.MethodPatch, "/api/v4/file/view", map[string]any{
				"uri": folder, "view": map[string]any{"view": "grid", "page_size": 50, "order_direction": "asc", "gallery_width": 200},
			}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			actor, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			_, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
			fm := manager.NewFileManager(f.dep, actor)
			defer fm.Recycle()
			uri, err := fs.NewUriFromString(folder)
			require.NoError(t, err)
			_, err = fm.Get(txCtx, uri)
			require.NoError(t, err)
			f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
				"uris": []string{folder}, "setting": map[string]string{"everyone": "AA=="},
			}, nil)
			view := &types.ExplorerView{View: "list", PageSize: 50, OrderDirection: "asc", GalleryWidth: 200}
			if clear {
				view = nil
			}
			require.NoError(t, fm.PatchView(txCtx, uri, view))
			require.NoError(t, inventory.Commit(tx))
			info := f.permissionInfo(t, folder)
			require.NotNil(t, info.ExtendedInfo.Permissions)
			require.Equal(t, []byte{0}, []byte(*info.ExtendedInfo.Permissions.Everyone), "view changes must preserve the committed ACL")
			if clear {
				require.Nil(t, info.ExtendedInfo.View)
			} else {
				require.Equal(t, "list", info.ExtendedInfo.View.View)
				require.Equal(t, 50, info.ExtendedInfo.View.PageSize)
			}
			require.Equal(t, []byte("retained view content"), f.readFile(t, folder+"/file.txt"))
		})
	}
}

func TestFilePermissionsUnchangedViewSeesFileCommittedAfterInheritedSnapshot(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read unchanged file update")
	}
	for _, clear := range []bool{false, true} {
		for _, commit := range []bool{false, true} {
			t.Run(fmt.Sprintf("clear=%t/commit=%t", clear, commit), func(t *testing.T) {
				f := newWritableShareFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				actor, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
				require.NoError(t, err)
				marker := f.db.Setting.Create().SetName("view_caller_marker").SetValue("original").SaveX(ctx)
				writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
				require.NoError(t, err)
				defer inventory.Rollback(tx)
				_, err = writer.GetClient().File.Query().Count(txCtx)
				require.NoError(t, err)
				writer.GetClient().Setting.UpdateOneID(marker.ID).SetValue("pending").ExecX(txCtx)
				const folder = "cloudreve://my/new-view"
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
				view := &types.ExplorerView{View: "list", PageSize: 50, OrderDirection: "asc", GalleryWidth: 200}
				if clear {
					view = nil
				}
				f.request(t, http.MethodPatch, "/api/v4/file/view", map[string]any{"uri": folder, "view": view}, nil)
				f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
					"uris": []string{folder}, "setting": map[string]string{"everyone": "AA=="},
				}, nil)
				fm := manager.NewFileManager(f.dep, actor)
				defer fm.Recycle()
				uri, err := fs.NewUriFromString(folder)
				require.NoError(t, err)
				target, err := fm.Get(ctx, uri)
				require.NoError(t, err)
				stamp := f.db.File.GetX(ctx, target.ID()).UpdatedAt
				f.db.File.Use(func(next ent.Mutator) ent.Mutator {
					return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
						mutation.(*ent.FileMutation).SetUpdatedAt(stamp)
						return next.Mutate(ctx, mutation)
					})
				})
				txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
				require.NoError(t, fm.PatchView(txCtx, uri, view))
				wrongOwner := *f.db.File.GetX(ctx, target.ID())
				wrongOwner.OwnerID = 1
				_, err = writer.UpdateProps(context.WithValue(txCtx, inventory.CurrentPermissionReadCtx{}, true), &wrongOwner, wrongOwner.Props)
				require.True(t, ent.IsNotFound(err), "current fallback must retain the owner predicate")
				require.Equal(t, "original", f.db.Setting.GetX(ctx, marker.ID).Value)
				if commit {
					require.NoError(t, inventory.Commit(tx))
					require.Equal(t, "pending", f.db.Setting.GetX(ctx, marker.ID).Value)
				} else {
					require.NoError(t, inventory.Rollback(tx))
					require.Equal(t, "original", f.db.Setting.GetX(ctx, marker.ID).Value)
				}
				props := f.db.File.GetX(ctx, target.ID()).Props
				require.Equal(t, view, props.View)
				require.Equal(t, []byte{0}, []byte(*props.Permissions.Everyone))
			})
		}
	}
}

func TestWritableShareRedelegationUsesCompleteOwnerLockOrder(t *testing.T) {
	f := newWritableShareFixture(t)
	if f.database.Type != "mysql" && f.database.Type != "postgres" {
		t.Skip("SQLite serializes independent writers")
	}
	ctx := context.Background()
	const folder = "cloudreve://my/lock-union"
	f.upload(t, folder+"/file.txt", []byte("delegated lock content"), nil)
	visitor, password := f.createWritableVisitor(t, 2)
	admin := f.db.Group.GetX(ctx, 1)
	boolset.Set(int(types.GroupPermissionShare), true, admin.Permissions)
	f.db.Group.UpdateOne(admin).SetPermissions(admin.Permissions).ExecX(ctx)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	ownerURI := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my/lock-union"
	original, shared := f.createWritableShare(t, ownerURI, map[string]any{"everyone": "Pw=="})
	createdFirst, deletedFirst, deletedSecond := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resumeCreate := make(chan struct{})
	var createOnce, resumed atomic.Bool
	var deleteWrites atomic.Int32
	resume := func() {
		if resumed.CompareAndSwap(false, true) {
			close(resumeCreate)
		}
	}
	t.Cleanup(resume)
	f.db.User.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, mutation entgo.Mutation) (entgo.Value, error) {
			m := mutation.(*ent.UserMutation)
			info := requestinfo.RequestInfoFromContext(ctx)
			_, locking := m.AddedStorage()
			if !locking || info == nil {
				return next.Mutate(ctx, mutation)
			}
			if info.UserAgent == "redelegate-lock-union" && createOnce.CompareAndSwap(false, true) {
				value, err := next.Mutate(ctx, mutation)
				if err != nil {
					return value, err
				}
				close(createdFirst)
				select {
				case <-resumeCreate:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return value, nil
			}
			if info.UserAgent == "delete-lock-union" {
				n := deleteWrites.Add(1)
				if n == 2 {
					close(deletedSecond)
				}
				value, err := next.Mutate(ctx, mutation)
				if n == 1 && err == nil {
					close(deletedFirst)
				}
				return value, err
			}
			return next.Mutate(ctx, mutation)
		})
	})
	f.loginAs(t, visitor.Email, password)
	creation := f.permissionAsyncRequest(t, http.MethodPut, "/api/v4/share", map[string]any{
		"uri": shared, "permissions": map[string]any{"everyone": "IQ=="},
	}, "redelegate-lock-union")
	awaitPermissionPause(t, createdFirst)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	deletion := f.permissionAsyncRequest(t, http.MethodDelete, "/api/v4/share/"+original, nil, "delete-lock-union")
	select {
	case <-deletedFirst:
		// The old create path holds owner 2 while deletion holds creator 1.
		awaitPermissionPause(t, deletedSecond)
	case <-time.After(time.Second):
		// A complete union already holds creator 1, so deletion waits there.
	}
	resume()
	created, deleted := awaitPermissionResult(t, creation), awaitPermissionResult(t, deletion)
	require.Zero(t, created.Code, "%s: %s", created.Msg, created.Error)
	require.Zero(t, deleted.Code, "%s: %s", deleted.Msg, deleted.Error)
	remaining := f.db.Share.Query().WithUser().WithFile().OnlyX(ctx)
	require.Equal(t, visitor.ID, remaining.Edges.User.ID)
	require.Equal(t, 2, remaining.Edges.File.OwnerID)
	f.loginAs(t, visitor.Email, password)
	uri := fs.NewShareUri(hashid.EncodeShareID(f.dep.HashIDEncoder(), remaining.ID), "")
	require.Equal(t, []byte("delegated lock content"), f.readFile(t, uri+"/file.txt"))
}

func TestFilePermissionsACLConflictReleasesLocks(t *testing.T) {
	f := newWritableShareFixture(t)
	for _, name := range []string{"changed.txt", "unchanged.txt"} {
		f.upload(t, "cloudreve://my/acl-retry/"+name, []byte("lock fixture"), nil)
	}
	uri := "cloudreve://my/acl-retry/changed.txt"
	body := map[string]any{
		"uris":    []string{uri, "cloudreve://my/acl-retry/unchanged.txt"},
		"setting": map[string]string{"everyone": "IQ=="},
	}
	reached, resume := pausePermissionFileRead(t, f, "changed.txt", "acl-conflict-retry")
	result := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/permission", body, "acl-conflict-retry")
	awaitPermissionPause(t, reached)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
		"uris": []string{uri}, "setting": map[string]string{"everyone": "AA=="},
	}, nil)
	resume()
	require.Equal(t, serializer.CodeConflict, awaitPermissionResult(t, result).Code)
	require.Nil(t, f.permissionInfo(t, "cloudreve://my/acl-retry/unchanged.txt").ExtendedInfo.Permissions)

	// A rejected batch must release every acquired lock, including those for
	// unchanged files. A fresh public request must succeed without unlocking.
	f.request(t, http.MethodPost, "/api/v4/file/permission", body, nil)
	for _, name := range []string{"changed.txt", "unchanged.txt"} {
		info := f.permissionInfo(t, "cloudreve://my/acl-retry/"+name)
		require.Equal(t, []byte{33}, []byte(*info.ExtendedInfo.Permissions.Everyone))
	}
}

func TestFilePermissionsShareDeleteRejectsAdminDemotedBeforeFence(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.upload(t, "cloudreve://my/delete-manager-fence/seed.txt", []byte("owner content"), nil)
			targetID, _ := f.createWritableShare(t, "cloudreve://my/delete-manager-fence", map[string]any{"everyone": "IQ=="})
			controlID, _ := f.createWritableShare(t, "cloudreve://my/delete-manager-fence", map[string]any{"everyone": "IQ=="})
			adminGroup := f.db.Group.GetX(context.Background(), 1)
			permissions := append(boolset.BooleanSet{}, (*adminGroup.Permissions)...)
			boolset.Set(int(types.GroupPermissionShare), true, &permissions)
			require.NoError(t, f.db.Group.UpdateOne(adminGroup).SetPermissions(&permissions).Exec(context.Background()))
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			f.request(t, http.MethodGet, "/api/v4/file?uri=cloudreve://my", nil, nil)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/own-link", "type": "folder"}, nil)
			ownID, _ := f.createWritableShare(t, "cloudreve://my/own-link", map[string]any{"everyone": "IQ=="})
			reached, release := make(chan struct{}), make(chan struct{})
			var triggered, released atomic.Bool
			resume := func() {
				if released.CompareAndSwap(false, true) {
					close(release)
				}
			}
			t.Cleanup(resume)
			f.db.Share.Intercept(entgo.InterceptFunc(func(next entgo.Querier) entgo.Querier {
				return entgo.QuerierFunc(func(ctx context.Context, q entgo.Query) (entgo.Value, error) {
					value, err := next.Query(ctx, q)
					info := requestinfo.RequestInfoFromContext(ctx)
					if err == nil && info != nil && info.UserAgent == "delete-manager-fence-paused" && triggered.CompareAndSwap(false, true) {
						close(reached)
						select {
						case <-release:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					return value, err
				})
			}))
			path := "/api/v4/share/" + targetID
			var body any
			if batch {
				path = "/api/v4/share"
				body = map[string]any{"ids": []string{ownID, targetID}}
			}
			result := f.permissionAsyncRequest(t, http.MethodDelete, path, body, "delete-manager-fence-paused")
			awaitPermissionPause(t, reached)
			// Native authentication has already loaded an administrator, but the
			// destructive transaction has not begun. Revoke that privilege first.
			require.NoError(t, f.db.User.UpdateOneID(1).SetGroupID(2).Exec(context.Background()))
			controlCode := f.responseCode(t, http.MethodDelete, "/api/v4/share/"+controlID, nil)
			require.NotZero(t, controlCode, "current actor cannot manage another owner's link")
			resume()
			observed := awaitPermissionResult(t, result)
			decoded, err := f.dep.HashIDEncoder().Decode(targetID, hashid.ShareID)
			require.NoError(t, err)
			_, err = f.db.Share.Get(context.Background(), decoded)
			deleted := ent.IsNotFound(err)
			t.Logf("demoted %s delete: fresh request code=%d; paused request code=%d; target deleted=%t", name, controlCode, observed.Code, deleted)
			require.NotZero(t, observed.Code, "share deletion must revalidate the actor after the permission fence")
			require.False(t, deleted)
			// Losing administrator status does not revoke management of one's own
			// link. In a rejected mixed batch that link must remain untouched.
			own, err := f.dep.HashIDEncoder().Decode(ownID, hashid.ShareID)
			require.NoError(t, err)
			_, err = f.db.Share.Get(context.Background(), own)
			require.NoError(t, err)
			f.request(t, http.MethodDelete, "/api/v4/share/"+ownID, nil, nil)
			f.login(t)
			f.request(t, http.MethodDelete, "/api/v4/share/"+targetID, nil, nil)
			// Inventory cleanup without an HTTP actor retains its trusted scope.
			control, err := f.dep.HashIDEncoder().Decode(controlID, hashid.ShareID)
			require.NoError(t, err)
			require.NoError(t, f.dep.ShareClient().DeleteBatch(context.Background(), []int{control}))
		})
	}
}

func TestFilePermissionsShareDeletionSeesLinksCommittedAfterInheritedSnapshot(t *testing.T) {
	for _, name := range []string{"single", "batch", "user-batch", "pending-batch"} {
		t.Run(name, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read missing links")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f.upload(t, "cloudreve://my/new-share/seed.txt", []byte("revocable content"), nil)
			original, source := f.createWritableShare(t, "cloudreve://my/new-share", map[string]any{"everyone": "Pw==", "anonymous": "IQ=="})
			owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.ShareClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, 1, writer.GetClient().Share.Query().CountX(txCtx))
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			visitor, password := f.createWritableVisitor(t, 2)
			// The new creator differs from the real file owner. Its ID must join
			// the sorted lock union before final authorization and deletion.
			f.loginAs(t, visitor.Email, password)
			created, target := f.createWritableShare(t, source, map[string]any{"everyone": "Lw==", "anonymous": "IQ=="})
			createdID, err := f.dep.HashIDEncoder().Decode(created, hashid.ShareID)
			require.NoError(t, err)
			originalID, err := f.dep.HashIDEncoder().Decode(original, hashid.ShareID)
			require.NoError(t, err)
			pendingID := 0
			switch name {
			case "batch":
				err = writer.DeleteBatch(txCtx, []int{originalID, createdID})
			case "user-batch":
				err = writer.DeleteBatchByUserID(txCtx, visitor.ID, []int{originalID, createdID})
			case "pending-batch":
				file := writer.GetClient().Share.GetX(txCtx, originalID).QueryFile().OnlyX(txCtx)
				pending, createErr := writer.Upsert(txCtx, &inventory.CreateShareParams{OwnerID: owner.ID, FileID: file.ID})
				require.NoError(t, createErr)
				pendingID = pending.ID
				err = writer.DeleteBatch(txCtx, []int{pendingID, createdID})
			default:
				err = writer.Delete(txCtx, createdID)
			}
			require.NoError(t, err)
			if name == "pending-batch" {
				require.NoError(t, inventory.Rollback(tx))
			} else {
				require.NoError(t, inventory.Commit(tx))
			}
			f.token = ""
			code := f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(target), nil)
			t.Logf("inherited %s deletion: new delegated link access code=%d", name, code)
			if name == "pending-batch" {
				require.Zero(t, code, "caller rollback must retain the committed link")
				_, err := f.db.Share.Get(ctx, pendingID)
				require.True(t, ent.IsNotFound(err), "caller rollback must discard its pending link")
			} else {
				require.NotZero(t, code, "successful revocation must close the newly committed link")
			}
			code = f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(source), nil)
			if name == "batch" {
				require.NotZero(t, code)
			} else {
				require.Zero(t, code, "single deletion must preserve the original link")
			}
		})
	}
}

func TestFilePermissionsShareDeleteUsesCurrentRoleInInheritedSnapshot(t *testing.T) {
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read role snapshots")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f.upload(t, "cloudreve://my/current-delete/seed.txt", []byte("retained content"), nil)
			target, _ := f.createWritableShare(t, "cloudreve://my/current-delete", map[string]any{"everyone": "IQ=="})
			visitor, password := f.createWritableVisitor(t, 2)
			f.loginAs(t, visitor.Email, password)
			f.upload(t, "cloudreve://my/own-link/seed.txt", []byte("own content"), nil)
			own, _ := f.createWritableShare(t, "cloudreve://my/own-link", map[string]any{"everyone": "IQ=="})
			group := *f.db.Group.GetX(ctx, 1)
			group.ID, group.Name = 0, "Temporary administrators"
			ids := []int{f.policies[0].ID}
			custom, err := f.dep.GroupClient().UpsertWithPolicies(ctx, &group, &ids)
			require.NoError(t, err)
			f.db.User.UpdateOneID(visitor.ID).SetGroupID(custom.ID).ExecX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.ShareClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			actor := writer.GetClient().User.Query().Where(entuser.ID(visitor.ID)).WithGroup().OnlyX(txCtx)
			require.True(t, actor.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)))
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
			permissions := append(boolset.BooleanSet{}, (*custom.Permissions)...)
			boolset.Set(int(types.GroupPermissionIsAdmin), false, &permissions)
			custom.Permissions = &permissions
			_, err = f.dep.GroupClient().UpsertWithPolicies(ctx, custom, nil)
			require.NoError(t, err)
			targetID, err := f.dep.HashIDEncoder().Decode(target, hashid.ShareID)
			require.NoError(t, err)
			ownID, err := f.dep.HashIDEncoder().Decode(own, hashid.ShareID)
			require.NoError(t, err)
			if batch {
				err = writer.DeleteBatch(txCtx, []int{ownID, targetID})
			} else {
				err = writer.Delete(txCtx, targetID)
			}
			require.NoError(t, inventory.Commit(tx))
			_, lookupErr := f.db.Share.Get(ctx, targetID)
			t.Logf("inherited %s deletion: error=%v; target deleted=%t", name, err, ent.IsNotFound(lookupErr))
			var denied serializer.AppError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, serializer.CodeNotFound, denied.Code)
			require.NoError(t, lookupErr)
			_, err = f.db.Share.Get(ctx, ownID)
			require.NoError(t, err, "a rejected mixed batch must preserve the actor's own link")
			// Revoking an administrator role still permits native own-link management.
			ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
			require.NoError(t, f.dep.ShareClient().Delete(ctx, ownID))
		})
	}
}

func TestFilePermissionsShareDeleteRejectsDisabledCreator(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/disabled-creator/seed.txt", []byte("creator content"), nil)
	id, _ := f.createWritableShare(t, "cloudreve://my/disabled-creator", map[string]any{"everyone": "IQ=="})
	reached, resume := pausePermissionFileRead(t, f, "disabled-creator", "disable-share-creator")
	result := f.permissionAsyncRequest(t, http.MethodDelete, "/api/v4/share/"+id, nil, "disable-share-creator")
	awaitPermissionPause(t, reached)
	require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(entuser.StatusManualBanned).Exec(context.Background()))
	resume()
	require.NotZero(t, awaitPermissionResult(t, result).Code)
	decoded, err := f.dep.HashIDEncoder().Decode(id, hashid.ShareID)
	require.NoError(t, err)
	_, err = f.db.Share.Get(context.Background(), decoded)
	require.NoError(t, err)
}

func TestFilePermissionsAdministratorManagesInactiveOwnerACL(t *testing.T) {
	f := newWritableShareFixture(t)
	const source = "cloudreve://my/admin-inactive/file.txt"
	f.upload(t, source, []byte("retained owner content"), nil)
	_, shared := f.createWritableShare(t, "cloudreve://my/admin-inactive", map[string]any{"everyone": "IQ=="})
	ownerID := hashid.EncodeUserID(f.dep.HashIDEncoder(), 2)
	uri := "cloudreve://" + ownerID + "@my/admin-inactive/file.txt"
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
		"uris": []string{uri}, "setting": map[string]string{"everyone": "IQ=="},
	}, nil)
	require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(entuser.StatusManualBanned).Exec(context.Background()))
	require.NotNil(t, f.permissionInfo(t, uri).ExtendedInfo.Permissions, "native administrator can inspect inactive owner's file")
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
		"uris": []string{uri}, "setting": map[string]string{"everyone": "AA=="},
	}, nil)
	require.Equal(t, []byte{0}, []byte(*f.permissionInfo(t, uri).ExtendedInfo.Permissions.Everyone))
	f.request(t, http.MethodDelete, "/api/v4/file/permission", map[string]any{"uris": []string{uri}}, nil)
	require.Nil(t, f.permissionInfo(t, uri).ExtendedInfo.Permissions)
	// The personal-filesystem administrative exception does not revive a link
	// whose underlying owner is inactive, even for the same administrator.
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(shared), nil))
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
		"uris": []string{shared + "/file.txt"}, "setting": map[string]string{"everyone": "IQ=="},
	}))
}

func TestFilePermissionsInactiveOwnerExceptionUsesCurrentActorAndEntry(t *testing.T) {
	for _, change := range []string{"demoted-admin", "disabled-admin", "disabled-owner-share"} {
		t.Run(change, func(t *testing.T) {
			f := newWritableShareFixture(t)
			f.upload(t, "cloudreve://my/admin-exception/file.txt", []byte("exception fence"), nil)
			_, shared := f.createWritableShare(t, "cloudreve://my/admin-exception", map[string]any{"everyone": "IQ=="})
			uri := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my/admin-exception/file.txt"
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			if change == "disabled-owner-share" {
				uri = shared + "/file.txt"
			} else {
				require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(entuser.StatusManualBanned).Exec(context.Background()))
			}
			reached, resume := pausePermissionFileRead(t, f, "file.txt", change)
			result := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
				"uris": []string{uri}, "setting": map[string]string{"everyone": "AA=="},
			}, change)
			awaitPermissionPause(t, reached)
			switch change {
			case "demoted-admin":
				require.NoError(t, f.db.User.UpdateOneID(1).SetGroupID(2).Exec(context.Background()))
			case "disabled-admin":
				require.NoError(t, f.db.User.UpdateOneID(1).SetStatus(entuser.StatusManualBanned).Exec(context.Background()))
			case "disabled-owner-share":
				require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(entuser.StatusManualBanned).Exec(context.Background()))
			}
			resume()
			require.NotZero(t, awaitPermissionResult(t, result).Code)
			require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(entuser.StatusActive).Exec(context.Background()))
			f.token = ""
			f.login(t)
			require.Nil(t, f.permissionInfo(t, "cloudreve://my/admin-exception/file.txt").ExtendedInfo.Permissions,
				"rejected administrative exception must not mutate the ACL")
		})
	}
}
