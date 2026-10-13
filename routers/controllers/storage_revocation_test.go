package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRevocationUsesFreshGrantsForNativeAndOIDCSessions(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	server := httptest.NewServer(f.router)
	t.Cleanup(server.Close)
	f.remote = server.URL
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	native := f.token
	f.oidcLogin(t)
	external := f.token
	// Enable native version retention to prove historical version reads too.
	_, err := f.db.User.UpdateOneID(2).SetSettings(&types.UserSetting{VersionRetention: true, VersionRetentionMax: 5}).Save(context.Background())
	require.NoError(t, err)
	f.token = native
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	uri := "cloudreve://my/history.txt"
	original := []byte("historical B version remains readable")
	f.upload(t, uri, original, b)
	var newer explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len("latest B version"), "policy_id": b, "entity_type": "version"}, &newer)
	f.finishUpload(t, newer, []byte("latest B version"))
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	require.Len(t, info.ExtendedInfo.Entities, 2)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.NotNil(t, listing.ContextHint)
	f.assignPolicies(t, f.policies[0].ID)
	for _, token := range []string{native, external} {
		f.token = token
		var policies []explorer.StoragePolicy
		f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
		require.Len(t, policies, 1)
		// Deliberately use the real stale cached navigator under the original JWT.
		raw, err := json.Marshal(map[string]any{"uri": "cloudreve://my/revoked.txt", "size": 1, "policy_id": b})
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req := httptest.NewRequest(http.MethodPut, "/api/v4/file/upload", bytes.NewReader(raw)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(dbfs.ContextHintHeader, listing.ContextHint.String())
		w := httptest.NewRecorder()
		f.router.ServeHTTP(w, req)
		cancel()
		var denied struct {
			Code int `json:"code"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &denied))
		require.Equal(t, serializer.CodeGroupNotAllowed, denied.Code)
		require.Equal(t, []byte("latest B version"), f.readFile(t, uri))
		for _, entity := range info.ExtendedInfo.Entities {
			var links explorer.FileURLResponse
			f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}, "entity": entity.ID}, &links)
			_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
			if entity.ID == info.PrimaryEntity {
				require.Equal(t, "latest B version", string(data))
			} else {
				require.Equal(t, original, data)
			}
		}
	}
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{uri}, "skip_soft_delete": true}, nil)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.Len(t, listing.Files, 1, "only the legacy pre-upgrade file remains")
}

func TestStorageIssuedSessionCompletesAtOriginalDestinationAfterRevoke(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	uri := "cloudreve://my/issued.txt"
	data := []byte("signed before revocation and completed in bucket B")
	var session explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data), "policy_id": b}, &session)
	token := f.token
	f.assignPolicies(t, f.policies[0].ID)
	f.token = token
	f.finishUpload(t, session, data)
	require.Equal(t, b, session.StoragePolicy.ID)
	require.Equal(t, data, f.readFile(t, uri))
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/new-revoked.txt", "size": 1, "policy_id": b}, nil, token)
	var denied struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &denied))
	require.Equal(t, serializer.CodeGroupNotAllowed, denied.Code)
	// An invented native session or callback proof cannot use the frozen policy.
	w = openIDRequest(t, f.router, http.MethodGet, "/api/v4/callback/s3/unknown-session/unknown-proof", nil, nil, token)
	require.NotEqual(t, http.StatusOK, w.Code)

	// Exercise the native cache expiry with a real short configured TTL.
	_, err := f.db.Setting.Create().SetName("upload_session_timeout").SetValue("2").Save(context.Background())
	require.NoError(t, err)
	require.NoError(t, f.dep.KV().Delete("setting_", "upload_session_timeout"))
	var expiring explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/expiring.txt", "size": 1}, &expiring)
	require.Eventually(t, func() bool {
		_, exists := f.dep.KV().Get(manager.UploadSessionCachePrefix + expiring.SessionID)
		return !exists
	}, 4*time.Second, 20*time.Millisecond)
	w = openIDRequest(t, f.router, http.MethodGet, "/api/v4/callback/s3/"+expiring.SessionID+"/"+expiring.CallbackSecret, nil, nil, token)
	var expired struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &expired))
	require.Equal(t, serializer.CodeUploadSessionExpired, expired.Code)
}
