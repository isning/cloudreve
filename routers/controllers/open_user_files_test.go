package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/schema"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestOpenUserFilesNativeNavigationAndAuthentication(t *testing.T) {
	f := newWritableShareFixture(t)
	payload := []byte("persisted target content, not the administrator's file")
	f.upload(t, "cloudreve://my/support/child/readme.txt", payload, nil)
	f.upload(t, "cloudreve://my/support/child/alpha.txt", []byte("target page alpha"), nil)
	f.upload(t, "cloudreve://my/support/child/beta.txt", []byte("target page beta"), nil)
	target := hashid.EncodeUserID(f.dep.HashIDEncoder(), 2)
	root := "cloudreve://" + target + "@my"
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var detail admin.GetUserResponse
	f.request(t, http.MethodGet, "/api/v4/admin/user/2", nil, &detail)
	require.Equal(t, 2, detail.ID)
	require.Equal(t, target, detail.HashID)
	f.upload(t, "cloudreve://my/support/child/readme.txt", []byte("administrator's separate content"), nil)
	var listing explorer.ListResponse
	for _, uri := range []string{root, root + "/support", root + "/support/child", root + "/support?name=readme.txt"} {
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
		require.Contains(t, listing.Parent.Path, target+"@my")
		require.NotEmpty(t, listing.Files)
		for _, entry := range listing.Files {
			require.Contains(t, entry.Path, target+"@my")
		}
	}
	seen := map[string]bool{}
	next := ""
	for page := 0; page < 3; page++ {
		var result explorer.ListResponse
		f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/file?uri=%s&page_size=1&page=%d&next_page_token=%s&order_by=name&order_direction=asc", url.QueryEscape(root+"/support/child"), page, url.QueryEscape(next)), nil, &result)
		require.Len(t, result.Files, 1)
		require.Contains(t, result.Files[0].Path, target+"@my")
		seen[result.Files[0].Name] = true
		next = result.Pagination.NextPageToken
	}
	require.Len(t, seen, 3)
	require.Equal(t, payload, f.readFile(t, root+"/support/child/readme.txt"))
	own := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 1) + "@my/support/child/readme.txt"
	require.Equal(t, []byte("administrator's separate content"), f.readFile(t, own))
	// A direct personal URI is never granted by a file ACL or a copied location.
	visitor, password := f.createWritableVisitor(t, 2)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
		"uris": []string{"cloudreve://my/support"}, "setting": map[string]any{"user_explicit": map[string]string{hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID): "Pw=="}},
	}, nil)
	f.loginAs(t, visitor.Email, password)
	for _, token := range []string{f.token, ""} {
		f.token = token
		require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(root+"/support/child"), nil))
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{root + "/support/child/readme.txt"}}))
	}
}

func TestOpenUserFilesManagementRetainsOwnerStorageQuotaAndActor(t *testing.T) {
	f := newWritableShareFixture(t)
	f.assignPolicies(t, f.policies[1].ID, f.policies[0].ID)
	root := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my"
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	actorStorage := f.db.User.GetX(context.Background(), 1).Storage
	targetStorage := f.db.User.GetX(context.Background(), 2).Storage
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": root + "/maintenance", "type": "folder"}, nil)
	payload := []byte("created by the real administrator in the target owner's storage")
	upload := f.upload(t, root+"/maintenance/new.txt", payload, nil)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), upload.StoragePolicy.ID)
	info := f.fileInfo(t, root+"/maintenance/new.txt")
	id, err := f.dep.HashIDEncoder().Decode(info.ID, hashid.FileID)
	require.NoError(t, err)
	persisted := f.db.File.GetX(context.Background(), id)
	require.Equal(t, 2, persisted.OwnerID)
	entity := f.db.Entity.GetX(context.Background(), persisted.PrimaryEntity)
	require.Equal(t, 1, entity.CreatedBy)
	require.Equal(t, f.policies[1].ID, entity.StoragePolicyEntities)
	require.EqualValues(t, targetStorage+int64(len(payload)), f.db.User.GetX(context.Background(), 2).Storage)
	require.EqualValues(t, actorStorage, f.db.User.GetX(context.Background(), 1).Storage)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": root + "/maintenance/new.txt", "new_name": "renamed.txt"}, nil)
	require.Equal(t, payload, f.readFile(t, root+"/maintenance/renamed.txt"))
	require.Equal(t, info.ID, f.fileInfo(t, root+"/maintenance/renamed.txt").ID)
	for _, category := range []types.AuditEvent{types.AuditFileCreate, types.AuditEntityUploaded, types.AuditFileRename} {
		logs := f.db.AuditLog.Query().Where(auditlog.FileID(id), auditlog.Type(int(category))).AllX(context.Background())
		require.Len(t, logs, 1, fmt.Sprint(category))
		require.Equal(t, 1, logs[0].UserID)
		require.False(t, logs[0].Content.Failed)
	}
	// Native failures must not create a file, charge either account or log success.
	beforeAudit := f.db.AuditLog.Query().Where(auditlog.Type(int(types.AuditFileCreate))).CountX(context.Background())
	beforeFiles := f.db.File.Query().Where(file.OwnerID(2)).CountX(context.Background())
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": root + "/maintenance/renamed.txt", "type": "folder"}))
	require.Equal(t, serializer.CodeInsufficientCapacity, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": root + "/maintenance/over-quota.txt", "size": 2 << 20}))
	require.Equal(t, beforeFiles, f.db.File.Query().Where(file.OwnerID(2)).CountX(context.Background()))
	require.Equal(t, beforeAudit, f.db.AuditLog.Query().Where(auditlog.Type(int(types.AuditFileCreate))).CountX(context.Background()))
	require.EqualValues(t, targetStorage+int64(len(payload)), f.db.User.GetX(context.Background(), 2).Storage)
	require.EqualValues(t, actorStorage, f.db.User.GetX(context.Background(), 1).Storage)
}

func TestOpenUserFilesRootLifecycle(t *testing.T) {
	f := newWritableShareFixture(t)
	shareID, _ := f.defaultShare(t, "initial-share")
	f.setDefaultShares(t, shareID)
	for _, scenario := range []string{"active-missing", "pending-existing", "inactive-missing", "banned-missing", "legacy", "done-removed"} {
		t.Run(scenario, func(t *testing.T) {
			target, password := f.createWritableVisitor(t, 2)
			root := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), target.ID) + "@my"
			require.False(t, f.db.File.Query().Where(file.OwnerID(target.ID), file.Name(inventory.RootFolderName)).ExistX(context.Background()))
			status := entuser.StatusActive
			switch scenario {
			case "pending-existing":
				f.db.File.Create().SetName(inventory.RootFolderName).SetType(int(types.FileTypeFolder)).SetOwnerID(target.ID).SaveX(context.Background())
			case "inactive-missing":
				status = entuser.StatusInactive
			case "banned-missing":
				status = entuser.StatusManualBanned
			case "legacy":
				f.db.User.UpdateOne(target).SetSettings(&types.UserSetting{Language: "zh-CN"}).ExecX(context.Background())
			case "done-removed":
				f.loginAs(t, target.Email, password)
				f.request(t, http.MethodGet, "/api/v4/file?uri=cloudreve://my", nil, nil)
				f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/initial-share"}}, nil)
			}
			f.db.User.UpdateOne(target).SetStatus(status).ExecX(context.Background())
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			var listing explorer.ListResponse
			for i := 0; i < 2; i++ {
				f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(root), nil, &listing)
			}
			fresh := f.db.User.GetX(context.Background(), target.ID)
			require.Equal(t, status, fresh.Status)
			require.Contains(t, listing.Parent.Path, hashid.EncodeUserID(f.dep.HashIDEncoder(), target.ID)+"@my")
			require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(target.ID), file.Name(inventory.RootFolderName)).CountX(context.Background()))
			switch scenario {
			case "active-missing":
				require.Len(t, listing.Files, 1)
				require.True(t, fresh.Settings.DefaultShares.Done)
			case "pending-existing", "inactive-missing", "banned-missing":
				require.Empty(t, listing.Files)
				require.False(t, fresh.Settings.DefaultShares.Done)
				require.Len(t, fresh.Settings.DefaultShares.Shares, 1)
				if scenario == "pending-existing" {
					f.loginAs(t, target.Email, password)
					f.request(t, http.MethodGet, "/api/v4/file?uri=cloudreve://my", nil, &listing)
					require.Len(t, listing.Files, 1)
					require.True(t, f.db.User.GetX(context.Background(), target.ID).Settings.DefaultShares.Done)
				}
			case "legacy":
				require.Empty(t, listing.Files)
				require.Nil(t, fresh.Settings.DefaultShares)
			case "done-removed":
				require.Empty(t, listing.Files)
				require.True(t, fresh.Settings.DefaultShares.Done)
			}
		})
	}
	// Invalid and deleted users have native errors, never a fallback administrator root.
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	deleted, _ := f.createWritableVisitor(t, 2)
	f.db.User.DeleteOne(deleted).ExecX(context.Background())
	for _, id := range []string{"invalid-id", hashid.EncodeUserID(f.dep.HashIDEncoder(), deleted.ID), hashid.EncodeUserID(f.dep.HashIDEncoder(), 999999)} {
		require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://"+id+"@my"), nil))
	}
	// Personal administrator access does not revive a disabled owner's share.
	f.login(t)
	f.upload(t, "cloudreve://my/inactive-share/readme.txt", []byte("private maintenance bytes"), nil)
	_, shareURI := f.createWritableShare(t, "cloudreve://my/inactive-share", map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	f.db.User.UpdateOneID(2).SetStatus(entuser.StatusInactive).ExecX(context.Background())
	f.token = ""
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	require.Equal(t, []byte("private maintenance bytes"), f.readFile(t, "cloudreve://"+hashid.EncodeUserID(f.dep.HashIDEncoder(), 2)+"@my/inactive-share/readme.txt"))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(shareURI), nil))
}

func TestOpenUserFilesRevocationRejectsPendingNativeMutation(t *testing.T) {
	for _, change := range []string{"demoted", "disabled", "target-deleted"} {
		t.Run(change, func(t *testing.T) {
			f := newWritableShareFixture(t)
			payload := []byte("unchanged after revoked administrator request")
			f.upload(t, "cloudreve://my/controlled/file.txt", payload, nil)
			original := f.fileInfo(t, "cloudreve://my/controlled/file.txt")
			id, err := f.dep.HashIDEncoder().Decode(original.ID, hashid.FileID)
			require.NoError(t, err)
			root := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my/controlled"
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			var listing explorer.ListResponse
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(root), nil, &listing)
			require.NotNil(t, listing.ContextHint)
			storage := f.db.User.GetX(context.Background(), 2).Storage
			logs := f.db.AuditLog.Query().Where(auditlog.FileID(id), auditlog.Type(int(types.AuditFileRename))).CountX(context.Background())
			reached, resume := pausePermissionFileRead(t, f, "file.txt", "open-user-files-"+change)
			pending := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": root + "/file.txt", "new_name": "must-not-commit.txt"}, "open-user-files-"+change)
			awaitPermissionPause(t, reached)
			switch change {
			case "demoted":
				f.db.User.UpdateOneID(1).SetGroupID(2).ExecX(context.Background())
			case "disabled":
				f.db.User.UpdateOneID(1).SetStatus(entuser.StatusManualBanned).ExecX(context.Background())
			case "target-deleted":
				f.db.User.DeleteOneID(2).ExecX(context.Background())
			}
			resume()
			require.NotZero(t, awaitPermissionResult(t, pending).Code)
			require.Equal(t, "file.txt", f.db.File.GetX(context.Background(), id).Name)
			require.Equal(t, logs, f.db.AuditLog.Query().Where(auditlog.FileID(id), auditlog.Type(int(types.AuditFileRename))).CountX(context.Background()))
			require.Equal(t, storage, f.db.User.GetX(schema.SkipSoftDelete(context.Background()), 2).Storage)
			// A cached context hint and the same bearer token confer no lasting authority.
			req := httptest.NewRequest(http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(root), nil)
			req.Header.Set("Authorization", "Bearer "+f.token)
			req.Header.Set("X-Cr-Context-Hint", listing.ContextHint.String())
			response := httptest.NewRecorder()
			f.router.ServeHTTP(response, req)
			var envelope permissionHTTPResult
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
			require.NotZero(t, envelope.Code)
			require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": root + "/denied-folder", "type": "folder"}))
			require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": root + "/denied-upload.txt", "size": 12}))
			require.False(t, f.db.File.Query().Where(file.OwnerID(2), file.Name("denied-folder")).ExistX(context.Background()))
			if change == "target-deleted" {
				ctx := context.WithValue(context.Background(), inventory.LoadUserGroup{}, true)
				actor, err := inventory.NewUserClient(f.db).GetByID(ctx, 1)
				require.NoError(t, err)
				m := manager.NewFileManager(f.dep, actor)
				defer m.Recycle()
				uri, err := fs.NewUriFromString(root + "/denied-lock.txt")
				require.NoError(t, err)
				_, err = m.Lock(ctx, time.Minute, actor, true, fs.LockApp(fs.ApplicationDAV), uri, "")
				require.Error(t, err, "a missing user has no ancestor to lock")
			}
		})
	}
}
