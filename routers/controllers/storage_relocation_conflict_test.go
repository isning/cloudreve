package controllers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationRejectsConcurrentContentAndOwnershipChanges(t *testing.T) {
	for _, change := range []string{"new_version", "primary", "delete", "owner", "parent_trash"} {
		t.Run(change, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			folder, uri := "cloudreve://my/conflicts", "cloudreve://my/conflicts/source.txt"
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
			f.upload(t, uri, []byte("original retained bytes"), nil)
			first := f.fileInfo(t, uri).PrimaryEntity
			if change == "primary" {
				var version explorer.UploadSessionResponse
				f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len("second original version"), "entity_type": "version"}, &version)
				f.finishUpload(t, version, []byte("second original version"))
			}
			backend, err := url.Parse(f.policies[1].Server)
			require.NoError(t, err)
			proxy := httputil.NewSingleHostReverseProxy(backend)
			started, release := make(chan struct{}), make(chan struct{})
			var once, releaseOnce sync.Once
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") {
					once.Do(func() { close(started) })
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				proxy.ServeHTTP(w, r)
			}))
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); server.Close() })
			require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Exec(context.Background()))
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			worker := launchStorageWorkerWithWorkflows(t, f)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			_ = worker.ready(t)
			select {
			case <-started:
			case <-time.After(20 * time.Second):
				t.Fatal("controlled target PUT did not start")
			}
			// A separate native API dependency writes the same database, exposing
			// conflicts even when the executing worker holds a local path lock.
			var expectedPrimary string
			switch change {
			case "new_version":
				var version explorer.UploadSessionResponse
				f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len("concurrent version wins"), "entity_type": "version"}, &version)
				f.finishUpload(t, version, []byte("concurrent version wins"))
				expectedPrimary = f.fileInfo(t, uri).PrimaryEntity
			case "primary":
				f.request(t, http.MethodPost, "/api/v4/file/version/current", map[string]any{"uri": uri, "version": first}, nil)
				expectedPrimary = first
			case "delete":
				f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{uri}, "skip_soft_delete": true}, nil)
			case "parent_trash":
				f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{folder}}, nil)
			case "owner":
				// There is no public ownership-transfer API. This controlled database
				// fault represents an administrative ownership change during I/O.
				require.NoError(t, f.db.File.Update().Where(file.OwnerID(2), file.Name("source.txt")).SetOwnerID(1).Exec(context.Background()))
			}
			releaseOnce.Do(func() { close(release) })
			f.waitForStorageTask(t, accepted.ID, "error")
			items, err := f.db.RelocationItem.Query().All(context.Background())
			require.NoError(t, err)
			for _, item := range items {
				require.NotEqual(t, relocationitem.StateCommitted, item.State)
			}
			if expectedPrimary != "" {
				require.Equal(t, expectedPrimary, f.fileInfo(t, uri).PrimaryEntity)
				expected := "original retained bytes"
				if change == "new_version" {
					expected = "concurrent version wins"
				}
				require.Equal(t, expected, string(f.readFile(t, uri)))
			} else if change == "delete" {
				count, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("source.txt")).Count(context.Background())
				require.NoError(t, err)
				require.Zero(t, count, "migration must not recreate a deleted file")
			} else if change == "owner" {
				model, err := f.db.File.Query().Where(file.Name("source.txt")).Only(context.Background())
				require.NoError(t, err)
				require.Equal(t, 1, model.OwnerID)
			} else {
				require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape(uri), nil))
			}
		})
	}
}
