package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/stretchr/testify/require"
)

type permissionHTTPResult struct {
	Code int `json:"code"`
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
