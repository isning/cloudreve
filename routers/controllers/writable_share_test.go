package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	enttask "github.com/cloudreve/Cloudreve/v4/ent/task"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func newWritableShareFixture(t *testing.T) *storageFixture {
	t.Helper()
	f := newAuditFixture(t)
	for _, id := range []int{2, 3} {
		g := f.db.Group.GetX(context.Background(), id)
		boolset.Set(types.GroupPermissionShareDownload, true, g.Permissions)
		if id == 2 {
			boolset.Set(types.GroupPermissionShare, true, g.Permissions)
			boolset.Set(14, true, g.Permissions)
		}
		require.NoError(t, f.db.Group.UpdateOneID(id).SetPermissions(g.Permissions).Exec(context.Background()))
		settings := types.GroupSetting{MaxWalkedFiles: 1000}
		if g.Settings != nil {
			settings = *g.Settings
			settings.MaxWalkedFiles = 1000
		}
		require.NoError(t, f.db.Group.UpdateOneID(id).SetSettings(&settings).Exec(context.Background()))
	}
	f.login(t)
	return f
}

func (f *storageFixture) createWritableVisitor(t *testing.T, group int) (*ent.User, string) {
	t.Helper()
	password := storageRandom(t)
	u, err := inventory.NewUserClient(f.db).Create(context.Background(), &inventory.NewUserArgs{
		Email: "visitor-" + storageRandom(t) + "@example.com", PlainPassword: password,
		GroupID: group, Status: entuser.StatusActive, SkipBootstrap: true,
	})
	require.NoError(t, err)
	return u, password
}

func (f *storageFixture) createWritableShare(t *testing.T, uri string, permissions map[string]any) (string, string) {
	t.Helper()
	var link string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": uri, "permissions": permissions}, &link)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	id := strings.TrimPrefix(parsed.Path, "/s/")
	require.NotContains(t, id, "/")
	return id, fs.NewShareUri(id, "")
}

func TestWritableShareCollaboratorUploadUsesOwnerStorageAndRecordsActor(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/existing.txt", []byte("existing"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "Lw==", "anonymous": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	// The visitor's personal quota is irrelevant to a shared destination.
	require.NoError(t, f.db.User.UpdateOne(visitor).SetStorage(1<<20).Exec(context.Background()))
	f.loginAs(t, visitor.Email, password)
	payload := []byte("uploaded by a collaborator into the owner's policy")
	f.upload(t, uri+"/new.txt", payload, nil)

	f.login(t)
	require.Equal(t, payload, f.readFile(t, "cloudreve://my/team/new.txt"))
	info := f.fileInfo(t, "cloudreve://my/team/new.txt")
	id, err := f.dep.HashIDEncoder().Decode(info.ID, hashid.FileID)
	require.NoError(t, err)
	file := f.db.File.GetX(context.Background(), id)
	require.Equal(t, 2, file.OwnerID)
	require.Equal(t, visitor.ID, f.db.Entity.GetX(context.Background(), file.PrimaryEntity).CreatedBy)
	require.EqualValues(t, len(payload)+len("existing"), f.db.User.GetX(context.Background(), 2).Storage)
	require.EqualValues(t, 1<<20, f.db.User.GetX(context.Background(), visitor.ID).Storage)
}

func TestWritableShareAnonymousCollectionDoesNotExposeOrOverwriteFiles(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/private.txt", []byte("private existing content"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
	f.token = ""
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
	require.Empty(t, listing.Files)
	for _, endpoint := range []string{
		"/api/v4/file/info?uri=" + url.QueryEscape(uri+"/private.txt"),
		"/api/v4/file/activities?uri=" + url.QueryEscape(uri+"/private.txt") + "&page_size=20",
	} {
		require.NotZero(t, f.responseCode(t, http.MethodGet, endpoint, nil))
	}
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri + "/private.txt"}}))
	require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/private.txt", "size": 6, "entity_type": "version"}))
	payload := []byte("anonymous submission")
	f.upload(t, uri+"/submitted.txt", payload, nil)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
	require.Empty(t, listing.Files, "completed and in-progress submissions stay private")
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": uri + "/submitted.txt", "new_name": "changed.txt"}))
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{uri + "/submitted.txt"}}))
	f.login(t)
	require.Equal(t, payload, f.readFile(t, "cloudreve://my/inbox/submitted.txt"))
	require.Equal(t, []byte("private existing content"), f.readFile(t, "cloudreve://my/inbox/private.txt"))
}

func TestWritableShareSpecificRulesChildInheritanceAndOwnerOnlySettings(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/nested/private.txt", []byte("private child"), nil)
	f.upload(t, "cloudreve://my/team/visible.txt", []byte("visible"), nil)
	visitor, password := f.createWritableVisitor(t, 2)
	userID := hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID)
	permissions := map[string]any{"everyone": "Lw==", "anonymous": "IQ==", "user_explicit": map[string]any{userID: "AA=="}}
	id, uri := f.createWritableShare(t, "cloudreve://my/team", permissions)
	var ownerInfo map[string]any
	f.request(t, http.MethodGet, "/api/v4/share/info/"+id, nil, &ownerInfo)
	require.Equal(t, permissions, ownerInfo["permission_setting"])
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil), "an explicit deny overrides the fallback")
	var visitorInfo map[string]any
	f.request(t, http.MethodGet, "/api/v4/share/info/"+id, nil, &visitorInfo)
	require.NotContains(t, visitorInfo, "permission_setting")
	require.Equal(t, "AA==", visitorInfo["permissions"])
	f.login(t)
	permissions = map[string]any{"everyone": "Lw==", "anonymous": "IQ==", "same_group": "IQ=="}
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/team", "permissions": permissions}, nil)
	// A root file ACL does not replace the independently configured link ACL.
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/team"}, "setting": map[string]string{"everyone": "AA==", "anonymous": "AA=="}}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/team/nested"}, "setting": map[string]string{"everyone": "AA==", "anonymous": "AA=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, "visible.txt", listing.Files[0].Name)
	require.Equal(t, []byte("visible"), f.readFile(t, uri+"/visible.txt"))
	require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/new.txt", "size": 2}))
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri + "/nested/private.txt"}}))
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{uri + "/nested"}, "setting": map[string]string{"everyone": "Pw=="}}))
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/team/nested"}}, nil)
	f.loginAs(t, visitor.Email, password)
	require.Equal(t, []byte("private child"), f.readFile(t, uri+"/nested/private.txt"))
}

func TestWritableShareRevokedAnonymousUploadsCanBeCancelledWithoutDeleteAccess(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/original.txt", []byte("original"), nil)
	for _, revoke := range []string{"permission", "link", "expiry"} {
		t.Run(revoke, func(t *testing.T) {
			f.login(t)
			id, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
			f.token = ""
			var upload explorer.UploadSessionResponse
			f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/pending.txt", "size": 16}, &upload)
			require.EqualValues(t, len("original")+16, f.db.User.GetX(context.Background(), 2).Storage)
			f.login(t)
			if revoke == "link" {
				f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
			} else if revoke == "expiry" {
				shareID, err := f.dep.HashIDEncoder().Decode(id, hashid.ShareID)
				require.NoError(t, err)
				require.NoError(t, f.db.Share.UpdateOneID(shareID).SetExpires(time.Now().Add(-time.Minute)).Exec(context.Background()))
			} else {
				f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/inbox", "permissions": map[string]string{"everyone": "IQ==", "anonymous": "IQ=="}}, nil)
			}
			f.token = ""
			require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/callback/s3/"+upload.SessionID+"/"+upload.CallbackSecret, nil))
			f.request(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"uri": uri + "/pending.txt", "id": upload.SessionID}, nil)
			require.EqualValues(t, len("original"), f.db.User.GetX(context.Background(), 2).Storage)
			f.login(t)
			require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/inbox/pending.txt"), nil))
		})
	}
}

func TestWritableShareAnonymousGrantRestrictionsApplyOnlyToNewAssignments(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/file.txt", []byte("existing"), nil)
	permissions := map[string]any{"everyone": "Lw==", "anonymous": "Lw=="}
	id, _ := f.createWritableShare(t, "cloudreve://my/team", permissions)
	g := f.db.Group.GetX(context.Background(), 2)
	boolset.Set(types.GroupPermissionSetAnonymousPermission, false, g.Permissions)
	require.NoError(t, f.db.Group.UpdateOneID(2).SetPermissions(g.Permissions).Exec(context.Background()))
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/team", "permissions": permissions, "expire": 3600}, nil)
	permissions["same_group"] = "IQ=="
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/team", "permissions": permissions}, nil)
	for _, setting := range []map[string]any{
		permissions, {"everyone": "Lw=="}, {"everyone": "QA==", "anonymous": "IQ=="},
		{"everyone": "IQ==", "anonymous": "IQ==", "user_explicit": map[string]string{"invalid!": "AQ=="}},
	} {
		require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/team", "permissions": setting}))
	}
	// Anonymous writes already assigned are not revoked by changing group14.
	f.token = ""
	f.upload(t, fs.NewShareUri(id, "")+"/allowed.txt", []byte("existing grant"), nil)
}

func TestWritableSharePathsAndCrossOwnerCopiesUseTheReceivingOwnersPolicies(t *testing.T) {
	f := newWritableShareFixture(t)
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetDirNameRule("owners/{uid}/{path}").SetFileNameRule("{originname}").Exec(context.Background()))
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/one", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/two", "type": "folder"}, nil)
	_, one := f.createWritableShare(t, "cloudreve://my/one", map[string]any{"everyone": "Lw==", "anonymous": "Lw=="})
	_, two := f.createWritableShare(t, "cloudreve://my/two", map[string]any{"everyone": "Lw==", "anonymous": "Lw=="})
	f.token = ""
	f.upload(t, one+"/same.txt", []byte("one"), nil)
	f.upload(t, two+"/same.txt", []byte("two"), nil)
	f.login(t)
	require.Equal(t, []byte("one"), f.readFile(t, "cloudreve://my/one/same.txt"))
	require.Equal(t, []byte("two"), f.readFile(t, "cloudreve://my/two/same.txt"))
	permissions := &boolset.BooleanSet{}
	boolset.Set(types.GroupPermissionShareDownload, true, permissions)
	g, err := f.db.Group.Create().SetName("Another owner").SetPermissions(permissions).SetStoragePolicyID(f.policies[1].ID).SetMaxStorage(1 << 20).SetSettings(&types.GroupSetting{MaxWalkedFiles: 1000}).Save(context.Background())
	require.NoError(t, err)
	visitor, password := f.createWritableVisitor(t, g.ID)
	f.loginAs(t, visitor.Email, password)
	f.upload(t, "cloudreve://my/source.txt", []byte("other policy"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/source.txt"}, "dst": one, "copy": true}, nil)
	f.login(t)
	w := f.binaryRequest(t, http.MethodPut, "/api/v4/file/content?uri="+url.QueryEscape("cloudreve://my/one/source.txt"), []byte("updated by recipient"), "", "")
	var result struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	info := f.fileInfo(t, "cloudreve://my/one/source.txt")
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), info.ExtendedInfo.Entities[0].StoragePolicy.ID)
}

func TestWritableShareUploadSentinelKeepsOwnerAndCannotDeleteCompletedContent(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/original.txt", []byte("original"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
	f.token = ""
	var session explorer.UploadSessionResponse
	payload := []byte("completed content survives a stale sentinel")
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/finished.txt", "size": len(payload)}, &session)
	raw, ok := f.dep.KV().Get(manager.UploadSessionCachePrefix + session.SessionID)
	require.True(t, ok)
	upload := raw.(fs.UploadSession)
	model := f.db.Task.GetX(context.Background(), upload.SentinelTaskID)
	require.Equal(t, 2, model.UserTasks, "anonymous upload cleanup belongs to the receiving account")
	f.finishUpload(t, session, payload)
	var state manager.UploadSentinelCheckTaskState
	require.NoError(t, json.Unmarshal([]byte(model.PrivateState), &state))
	// A stale task must not even construct a provider after completion.
	state.Session.Policy.Type = "completed-upload-must-not-contact-provider"
	serialized, err := json.Marshal(state)
	require.NoError(t, err)
	model.PrivateState = string(serialized)
	// Exercise a stale persisted worker state as well as the completed-task guard.
	require.NoError(t, f.db.Task.UpdateOne(model).SetStatus(enttask.StatusQueued).Exec(context.Background()))
	owner, err := f.dep.UserClient().GetByID(context.WithValue(context.Background(), inventory.LoadUserGroup{}, true), 2)
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), dependency.DepCtx{}, f.dep)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	status, err := manager.NewUploadSentinelCheckTaskFromModel(model).Do(ctx)
	require.NoError(t, err)
	require.Equal(t, enttask.StatusCompleted, status)
	f.login(t)
	require.Equal(t, payload, f.readFile(t, "cloudreve://my/inbox/finished.txt"))
}

func TestWritableShareAnonymousRelayUploadAndUpdateAreAuthorizedSeparately(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/original.txt", []byte("original"), nil)
	settings := *f.policies[0].Settings
	settings.Relay = true
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetSettings(&settings).Exec(context.Background()))
	_, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
	f.token = ""
	var upload explorer.UploadSessionResponse
	payload := []byte("anonymous relay submission")
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/relay.txt", "size": len(payload)}, &upload)
	w := f.binaryRequest(t, http.MethodPost, "/api/v4/file/upload/"+upload.SessionID+"/0", payload, "", "")
	var result struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Zero(t, result.Code, w.Body.String())
	f.login(t)
	require.Equal(t, payload, f.readFile(t, "cloudreve://my/inbox/relay.txt"))
}

func TestWritableShareCopyMoveAndDelegationRetainTheRealFileOwner(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/original.txt", []byte("owner"), nil)
	visitor, password := f.createWritableVisitor(t, 2)
	id, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "IQ==", "anonymous": "IQ==", "user_explicit": map[string]string{hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID): "Pw=="}})
	f.loginAs(t, visitor.Email, password)
	f.upload(t, "cloudreve://my/copy.txt", []byte("copy"), nil)
	f.upload(t, "cloudreve://my/move.txt", []byte("move"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/copy.txt"}, "dst": uri, "copy": true}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/move.txt"}, "dst": uri}, nil)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/move.txt"), nil))
	delegatedID, delegatedURI := f.createWritableShare(t, uri, map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	require.NotEqual(t, id, delegatedID)
	var info struct {
		Owner struct {
			ID string `json:"id"`
		} `json:"owner"`
		SourceURI string `json:"source_uri"`
	}
	f.request(t, http.MethodGet, "/api/v4/share/info/"+delegatedID+"?owner_extended=true", nil, &info)
	require.Equal(t, hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID), info.Owner.ID)
	f.request(t, http.MethodPost, "/api/v4/share/"+delegatedID, map[string]any{"uri": info.SourceURI, "permissions": map[string]string{"everyone": "IQ==", "anonymous": "IQ=="}}, nil)
	f.token = ""
	require.Equal(t, []byte("copy"), f.readFile(t, delegatedURI+"/copy.txt"))
	f.login(t)
	require.Equal(t, []byte("move"), f.readFile(t, "cloudreve://my/team/move.txt"))
	require.EqualValues(t, len("owner")+len("copy")+len("move"), f.db.User.GetX(context.Background(), 2).Storage)
	require.EqualValues(t, len("copy"), f.db.User.GetX(context.Background(), visitor.ID).Storage)
}

func TestWritableShareFileOwnerCanManageDelegatedLinksWithoutChangingTheirCreator(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/file.txt", []byte("content"), nil)
	delegate, password := f.createWritableVisitor(t, 2)
	_, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{
		"everyone": "IQ==", "anonymous": "IQ==",
		"user_explicit": map[string]string{hashid.EncodeUserID(f.dep.HashIDEncoder(), delegate.ID): "Pw=="},
	})
	f.loginAs(t, delegate.Email, password)
	id, _ := f.createWritableShare(t, uri, map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	f.login(t)
	info := f.fileInfo(t, "cloudreve://my/team")
	var delegated *explorer.Share
	for i := range info.ExtendedInfo.Shares {
		if info.ExtendedInfo.Shares[i].ID == id {
			delegated = &info.ExtendedInfo.Shares[i]
		}
	}
	require.NotNil(t, delegated)
	require.Equal(t, hashid.EncodeUserID(f.dep.HashIDEncoder(), delegate.ID), delegated.Owner.ID)
	require.NotNil(t, delegated.PermissionSetting)
	f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": "cloudreve://my/team", "permissions": map[string]string{"everyone": "AA==", "anonymous": "AA=="}}, nil)
	f.loginAs(t, delegate.Email, password)
	var mine explorer.Share
	f.request(t, http.MethodGet, "/api/v4/share/info/"+id+"?owner_extended=true", nil, &mine)
	require.Equal(t, delegated.Owner.ID, mine.Owner.ID)
	require.NotNil(t, mine.PermissionSetting)
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
	f.token = ""
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/share/info/"+id, nil))
	// Unrelated authenticated visitors cannot edit or batch-delete another link.
	f.login(t)
	id, _ = f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	f.loginAs(t, delegate.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{"uri": fs.NewShareUri(id, ""), "permissions": map[string]string{"everyone": "Pw=="}}))
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/share", map[string]any{"ids": []string{id}}))
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/share", map[string]any{"ids": []string{id}}, nil)
}

func TestWritableShareAdministratorCanEditAndReadFileACLAndPrivateShareSettings(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/file.txt", []byte("content"), nil)
	var link string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{
		"uri": "cloudreve://my/team", "is_private": true, "password": "testpass",
		"permissions": map[string]string{"everyone": "Lw==", "anonymous": "Lw=="},
	}, &link)
	id := strings.Split(strings.TrimPrefix(mustParseSharePath(t, link), "/s/"), "/")[0]
	f.token = ""
	var locked explorer.Share
	f.request(t, http.MethodGet, "/api/v4/share/info/"+id, nil, &locked)
	require.False(t, locked.Unlocked)
	require.Nil(t, locked.Permissions)
	require.Nil(t, locked.PermissionSetting)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(fs.NewShareUri(id, "wrong")), nil))
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	ownerURI := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my/team/file.txt"
	setting := map[string]string{"everyone": "IQ==", "anonymous": "IQ=="}
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{ownerURI}, "setting": setting}, nil)
	adminInfo := f.fileInfo(t, ownerURI)
	require.NotNil(t, adminInfo.ExtendedInfo.Permissions)
	require.Equal(t, *types.ReadOnlyPermissions(), *adminInfo.ExtendedInfo.Permissions.Everyone)
	var managed explorer.Share
	f.request(t, http.MethodGet, "/api/v4/share/info/"+id+"?owner_extended=true", nil, &managed)
	require.True(t, managed.Unlocked)
	require.NotEmpty(t, managed.SourceUri)
	require.NotNil(t, managed.PermissionSetting)
}

func mustParseSharePath(t *testing.T, link string) string {
	t.Helper()
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	return parsed.Path
}

func TestWritableShareExpiredUploadWorkerCleansUpWithoutItsLinkAndRejectsOtherUsers(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/original.txt", []byte("original"), nil)
	id, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var upload explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/pending.txt", "size": 16}, &upload)
	f.token = ""
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"uri": uri + "/pending.txt", "id": upload.SessionID}))
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
	raw, ok := f.dep.KV().Get(manager.UploadSessionCachePrefix + upload.SessionID)
	require.True(t, ok)
	session := raw.(fs.UploadSession)
	model := f.db.Task.GetX(context.Background(), session.SentinelTaskID)
	owner, err := f.dep.UserClient().GetByID(context.WithValue(context.Background(), inventory.LoadUserGroup{}, true), 2)
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), dependency.DepCtx{}, f.dep)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	status, err := manager.NewUploadSentinelCheckTaskFromModel(model).Do(ctx)
	require.NoError(t, err)
	require.Equal(t, enttask.StatusCompleted, status)
	require.EqualValues(t, len("original"), f.db.User.GetX(context.Background(), 2).Storage)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/inbox/pending.txt"), nil))
	require.Equal(t, []byte("original"), f.readFile(t, "cloudreve://my/inbox/original.txt"))
}
