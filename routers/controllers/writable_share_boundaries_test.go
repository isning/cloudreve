package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	enttask "github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestWritableShareCollectionIdempotentCreateCannotInspectExistingFiles(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/private.txt", []byte("private content"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
	f.token = ""
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": uri + "/private.txt", "type": "file"}))
	f.login(t)
	require.Equal(t, []byte("private content"), f.readFile(t, "cloudreve://my/inbox/private.txt"))
}

func TestWritableShareDeletingADelegateRemovesTheirLinksAndKeepsTheReceiversFiles(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/file.txt", []byte("receiver content"), nil)
	delegate, password := f.createWritableVisitor(t, 2)
	originalID, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{
		"everyone": "IQ==", "anonymous": "IQ==",
		"user_explicit": map[string]string{hashid.EncodeUserID(f.dep.HashIDEncoder(), delegate.ID): "Pw=="},
	})
	f.loginAs(t, delegate.Email, password)
	id, _ := f.createWritableShare(t, uri, map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPost, "/api/v4/admin/user/batch/delete", map[string]any{"ids": []int{delegate.ID}}, nil)
	f.login(t)
	info := f.fileInfo(t, "cloudreve://my/team")
	require.Len(t, info.ExtendedInfo.Shares, 1)
	require.Equal(t, originalID, info.ExtendedInfo.Shares[0].ID)
	require.Equal(t, []byte("receiver content"), f.readFile(t, "cloudreve://my/team/file.txt"))
	f.token = ""
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/share/info/"+id, nil))
}

func TestWritableShareDestructiveParentOperationsRespectHiddenDescendants(t *testing.T) {
	f := newWritableShareFixture(t)
	for _, grant := range []string{"IQ==", "AA=="} {
		for _, operation := range []string{"trash", "delete", "move"} {
			t.Run(grant+operation, func(t *testing.T) {
				f.login(t)
				parent := "cloudreve://my/team/" + operation + fmt.Sprint(grant == "AA==")
				f.upload(t, parent+"/private/file.txt", []byte("protected descendant"), nil)
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/team/destination", "type": "folder"}, nil)
				f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
					"uris": []string{parent + "/private"}, "setting": map[string]string{"everyone": grant, "anonymous": grant},
				}, nil)
				_, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "Lw==", "anonymous": "Lw=="})
				parsed, err := fs.NewUriFromString(parent)
				require.NoError(t, err)
				f.token = ""
				target := uri + "/" + parsed.Name()
				if operation == "move" {
					require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{target}, "dst": uri + "/destination"}))
				} else {
					require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{target}, "skip_soft_delete": operation == "delete"}))
				}
				f.login(t)
				require.Equal(t, []byte("protected descendant"), f.readFile(t, parent+"/private/file.txt"))
			})
		}
	}
}

func TestWritableShareSingleFileCannotReachOrDelegateItsParent(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/allowed.txt", []byte("allowed"), nil)
	f.upload(t, "cloudreve://my/team/sibling/private.txt", []byte("secret sibling"), nil)
	visitor, password := f.createWritableVisitor(t, 2)
	_, uri := f.createWritableShare(t, "cloudreve://my/team/allowed.txt", map[string]any{
		"everyone": "Lw==", "anonymous": "Lw==",
		"user_explicit": map[string]string{hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID): "Pw=="},
	})
	f.token = ""
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.True(t, listing.SingleFileView)
	require.Equal(t, []byte("allowed"), f.readFile(t, uri+"/allowed.txt"))
	// Recursive consumers such as archive creation must see only the linked
	// file, not siblings beneath its artificial navigational parent.
	anonymous, err := f.dep.UserClient().AnonymousUser(context.Background())
	require.NoError(t, err)
	fm := manager.NewFileManager(f.dep, anonymous)
	defer fm.Recycle()
	root, err := fs.NewUriFromString(uri)
	require.NoError(t, err)
	walked := []string{}
	require.NoError(t, fm.Walk(context.Background(), root, 64, func(file fs.File, _ int) error {
		walked = append(walked, file.Name())
		return nil
	}))
	require.Equal(t, []string{"allowed.txt"}, walked)
	updated := []byte("edited linked file")
	response := f.binaryRequest(t, http.MethodPut, "/api/v4/file/content?uri="+url.QueryEscape(uri+"/allowed.txt"), updated, "", "")
	var result storageResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.Zero(t, result.Code)
	for _, path := range []string{"sibling/private.txt", "new-folder/submission.txt", "other.txt"} {
		require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape(uri+"/"+path), nil))
		require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/" + path, "size": 3}))
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": uri + "/" + path, "type": "folder"}))
	}
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": uri, "permissions": map[string]string{"everyone": "IQ==", "anonymous": "IQ=="}}))
	_, delegated := f.createWritableShare(t, uri+"/allowed.txt", map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	f.token = ""
	require.Equal(t, updated, f.readFile(t, delegated+"/allowed.txt"))
	f.login(t)
	require.Equal(t, []byte("secret sibling"), f.readFile(t, "cloudreve://my/team/sibling/private.txt"))
}

func TestWritableShareCopyNeverTransfersAnUploadCapability(t *testing.T) {
	f := newWritableShareFixture(t)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/team", "type": "folder"}, nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "Lw==", "anonymous": "Lw=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.token = ""
	var upload explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/pending.txt", "size": 8}, &upload)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{uri + "/pending.txt"}, "dst": "cloudreve://my", "copy": true}, nil)
	info := f.fileInfo(t, "cloudreve://my/pending.txt")
	require.NotContains(t, info.Metadata, dbfs.MetadataUploadSessionID)
	raw, err := json.Marshal(info)
	require.NoError(t, err)
	require.NotContains(t, string(raw), upload.SessionID)
	f.token = ""
	f.request(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"id": upload.SessionID, "uri": uri + "/pending.txt"}, nil)
}

func TestWritableShareCancelledReplacementRejectsAStaleCompletionSnapshot(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/file.txt", []byte("original"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "Lw==", "anonymous": "Lw=="})
	f.token = ""
	var upload explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/file.txt", "size": 16, "entity_type": "version"}, &upload)
	raw, ok := f.dep.KV().Get(manager.UploadSessionCachePrefix + upload.SessionID)
	require.True(t, ok)
	session := raw.(fs.UploadSession)
	// Model the SQL interleaving after completion has validated and loaded its
	// snapshot, but cancellation commits before it upgrades that entity.
	snapshot, err := f.dep.FileClient().GetByID(context.WithValue(context.Background(), inventory.LoadFileEntity{}, true), session.FileID)
	require.NoError(t, err)
	f.request(t, http.MethodDelete, "/api/v4/file/upload", map[string]string{"id": upload.SessionID, "uri": uri + "/file.txt"}, nil)
	fc, tx, ctx, err := inventory.WithTx(context.Background(), f.dep.FileClient())
	require.NoError(t, err)
	err = fc.UpgradePlaceholder(ctx, snapshot, nil, session.EntityID, types.EntityTypeVersion)
	require.Error(t, err, "a cancelled, unlinked entity must not be promoted by stale validation")
	require.NoError(t, inventory.Rollback(tx))
	f.login(t)
	require.Equal(t, []byte("original"), f.readFile(t, "cloudreve://my/team/file.txt"))
	require.EqualValues(t, len("original"), f.db.User.GetX(context.Background(), 2).Storage)
	require.Len(t, f.fileInfo(t, "cloudreve://my/team/file.txt").ExtendedInfo.Entities, 1)
}

func TestWritableShareAnonymousDerivedTasksResumeAsReceiverWithoutTheLink(t *testing.T) {
	f := newWritableShareFixture(t)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]string{"uri": "cloudreve://my/inbox", "type": "folder"}, nil)
	id, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "BA==", "anonymous": "BA=="})
	extractor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		require.NoError(t, err)
		_, _ = io.WriteString(w, "received document text")
	}))
	t.Cleanup(extractor.Close)
	for name, value := range map[string]string{
		"fts_enabled": "1", "fts_extractor_type": "tika", "fts_tika_endpoint": extractor.URL, "fts_tika_exts": "txt",
	} {
		require.NoError(t, f.db.Setting.Create().SetName(name).SetValue(value).OnConflictColumns("name").UpdateNewValues().Exec(context.Background()))
	}
	f.token = ""
	f.upload(t, uri+"/document.txt", []byte("document text"), nil)
	model := f.db.Task.Query().Where(enttask.Type(queue.FullTextIndexTaskType)).OnlyX(context.Background())
	require.Equal(t, 2, model.UserTasks)
	var state manager.FullTextIndexTaskState
	require.NoError(t, json.Unmarshal([]byte(model.PrivateState), &state))
	require.Equal(t, "my", string(state.Uri.FileSystem()))
	require.NotContains(t, state.Uri.String(), id+"@share")
	f.login(t)
	f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
	owner, err := f.dep.UserClient().GetByID(context.WithValue(context.Background(), inventory.LoadUserGroup{}, true), model.UserTasks)
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), dependency.DepCtx{}, f.dep)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	status, err := manager.NewFullTextIndexTaskFromModel(model).Do(ctx)
	require.NoError(t, err)
	require.Equal(t, enttask.StatusCompleted, status)
	info := f.fileInfo(t, "cloudreve://my/inbox/document.txt")
	require.Contains(t, info.Metadata, dbfs.FullTextIndexKey)
}

func TestWritableShareCancelledProviderAbortCanRetryAfterDatabaseCleanup(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/inbox/original.txt", []byte("original"), nil)
	upstream, err := url.Parse(f.policies[0].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Query().Has("uploadId") && attempts.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<Error><Code>InvalidRequest</Code><Message>injected abort failure</Message></Error>")
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetServer(server.URL).Exec(context.Background()))
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			attempts.Store(0)
			f.login(t)
			_, uri := f.createWritableShare(t, "cloudreve://my/inbox", map[string]any{"everyone": "Lw==", "anonymous": "Lw=="})
			body := map[string]any{"uri": uri + "/new.txt", "size": 16}
			if replace {
				body["uri"], body["entity_type"] = uri+"/original.txt", "version"
			}
			f.token = ""
			var upload explorer.UploadSessionResponse
			f.request(t, http.MethodPut, "/api/v4/file/upload", body, &upload)
			raw, ok := f.dep.KV().Get(manager.UploadSessionCachePrefix + upload.SessionID)
			require.True(t, ok)
			session := raw.(fs.UploadSession)
			require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/file/upload", map[string]any{"id": upload.SessionID, "uri": body["uri"]}))
			require.EqualValues(t, 1, attempts.Load())
			require.EqualValues(t, len("original"), f.db.User.GetX(context.Background(), 2).Storage)
			// Resume the persisted sentinel without an in-memory session cache.
			require.NoError(t, f.dep.KV().Delete(manager.UploadSessionCachePrefix, upload.SessionID))
			model := f.db.Task.GetX(context.Background(), session.SentinelTaskID)
			owner, err := f.dep.UserClient().GetByID(context.WithValue(context.Background(), inventory.LoadUserGroup{}, true), 2)
			require.NoError(t, err)
			ctx := context.WithValue(context.Background(), dependency.DepCtx{}, f.dep)
			ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
			status, err := manager.NewUploadSentinelCheckTaskFromModel(model).Do(ctx)
			require.NoError(t, err)
			require.Equal(t, enttask.StatusCompleted, status)
			require.EqualValues(t, 2, attempts.Load())
			f.login(t)
			require.Equal(t, []byte("original"), f.readFile(t, "cloudreve://my/inbox/original.txt"))
		})
	}
}
