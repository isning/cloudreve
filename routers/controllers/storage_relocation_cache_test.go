package controllers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationWarmURLsFollowTwoLocatorChanges(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	token := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["settings"] = map[string]any{"source_batch": 100, "redirected_source": true}
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = token
	uri := "cloudreve://my/cached.txt"
	f.upload(t, uri, []byte("cached retained version"), nil)
	first := f.fileInfo(t, uri).PrimaryEntity
	var version explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len("cached current version"), "entity_type": "version"}, &version)
	f.finishUpload(t, version, []byte("cached current version"))
	before := f.fileInfo(t, uri)
	var direct []explorer.DirectLinkResponse
	f.request(t, http.MethodPut, "/api/v4/file/source", map[string]any{"uris": []string{uri}}, &direct)
	require.Len(t, direct, 1)
	permanent, err := url.Parse(direct[0].Link)
	require.NoError(t, err)
	require.Equal(t, "/f/", permanent.Path[:3])

	check := func(bucket string) {
		t.Helper()
		for _, entity := range []string{"", first} {
			var links explorer.FileURLResponse
			f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}, "entity": entity}, &links)
			require.Len(t, links.Urls, 1)
			require.True(t, strings.Contains(links.Urls[0].Url, bucket), "new native content/version request must use committed bucket")
			_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
			expected := "cached current version"
			if entity != "" {
				expected = "cached retained version"
			}
			require.Equal(t, expected, string(data))
		}
		request := httptest.NewRequest(http.MethodGet, permanent.RequestURI(), nil)
		recorder := httptest.NewRecorder()
		f.router.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusFound, recorder.Code)
		location := recorder.Header().Get("Location")
		require.True(t, strings.Contains(location, bucket), "same permanent link must redirect to committed bucket")
		_, data := storageHTTP(t, http.MethodGet, location, nil)
		require.Equal(t, "cached current version", string(data))
	}
	// Every read is served by this same long-lived API dependency/cache. The
	// independent worker commits location changes into the actual database.
	check(f.policies[0].BucketName)
	var worker *storageWorker
	for _, target := range []int{1, 0} {
		var accepted explorer.TaskResponse
		f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[target].ID)}, &accepted)
		if worker == nil {
			worker = launchStorageWorkerWithWorkflows(t, f)
		}
		remote := worker.ready(t)
		f.waitForStorageTask(t, accepted.ID, "completed")
		f.remote = ""
		check(f.policies[target].BucketName)
		after := f.fileInfo(t, uri)
		require.Equal(t, before.ID, after.ID)
		require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
		require.Len(t, after.ExtendedInfo.Entities, 2)
		f.request(t, http.MethodPut, "/api/v4/file/source", map[string]any{"uris": []string{uri}}, &direct)
		require.Equal(t, permanent.String(), direct[0].Link)
		f.remote = remote
	}
	count, err := f.db.DirectLink.Query().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, count)
}
