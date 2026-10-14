package controllers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageOfflineDownloadIncompleteNodeConfiguration(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		settings *types.NodeSetting
		message  string
	}{
		{"missing_settings", nil, "downloader not configured for this node"},
		{"aria2", &types.NodeSetting{Provider: types.DownloaderProviderAria2}, "aria2 settings missing for this node"},
		{"qbittorrent", &types.NodeSetting{Provider: types.DownloaderProviderQBittorrent}, "qbittorrent settings missing for this node"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			token := f.token
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			group := f.groupDetail(t)
			permissions, err := boolset.FromString(group["permissions"].(string))
			require.NoError(t, err)
			boolset.Set(int(types.GroupPermissionRemoteDownload), true, permissions)
			group["permissions"] = permissions
			f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
			f.token = token

			ctx := context.Background()
			master, err := f.db.Node.Get(ctx, 1)
			require.NoError(t, err)
			boolset.Set(int(types.NodeCapabilityRemoteDownload), true, master.Capabilities)
			_, err = f.db.Node.UpdateOne(master).SetCapabilities(master.Capabilities).
				SetSettings(scenario.settings).Save(ctx)
			require.NoError(t, err)
			_, err = f.db.Setting.Create().SetName("queue_remote_download_max_retry").SetValue("0").Save(ctx)
			require.NoError(t, err)

			var accepted []explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/download", map[string]any{
				"src": []string{"https://example.com/result.bin"}, "dst": "cloudreve://my/",
			}, &accepted)
			require.Len(t, accepted, 1)
			worker := launchStorageWorkerWithWorkflows(t, f)
			f.remote = worker.ready(t)
			f.login(t)
			failed := f.waitForStorageTaskCategory(t, accepted[0].ID, "error", "downloaded")
			require.Contains(t, failed.Error, "failed to create downloader")
			require.Contains(t, failed.Error, scenario.message)
			require.NotContains(t, failed.Error, "panic")
		})
	}
}

// Only the external aria2 protocol is controlled. Its addUri downloads real
// HTTP bytes into the supplied owned directory; native workflows perform all
// validation, uploads, callbacks, accounting and Task persistence.
func TestStorageOfflineDownloadRetainsAuthorizedDestination(t *testing.T) {
	for _, scenario := range []string{"success", "rebound", "size", "suffix", "revoked", "external_error"} {
		t.Run(scenario, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			token := f.token
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			group := f.groupDetail(t)
			bs, err := boolset.FromString(group["permissions"].(string))
			require.NoError(t, err)
			boolset.Set(int(types.GroupPermissionRemoteDownload), true, bs)
			group["permissions"] = bs
			f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
			f.token = token
			folder := "cloudreve://my/offline"
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
			f.bindFolder(t, folder, 1)
			payload := []byte("external HTTP download transferred to the fixed bucket")
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
			defer source.Close()
			downloadTempRoot := t.TempDir()
			var savedDir string
			var mu sync.Mutex
			var calls atomic.Int32
			paused, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID     json.RawMessage   `json:"id"`
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid external request", 400)
					return
				}
				var result any = "fixture-gid"
				switch req.Method {
				case "aria2.addUri":
					var urls []string
					var options map[string]any
					if len(req.Params) != 2 || json.Unmarshal(req.Params[0], &urls) != nil || len(urls) != 1 || json.Unmarshal(req.Params[1], &options) != nil {
						http.Error(w, "invalid addUri", 400)
						return
					}
					dir, ok := options["dir"].(string)
					if !ok {
						http.Error(w, "missing owned directory", 400)
						return
					}
					owned := downloadTempRoot
					relative, err := filepath.Rel(owned, dir)
					if err != nil || relative == ".." || filepath.IsAbs(relative) {
						http.Error(w, "unowned directory", 400)
						return
					}
					response, err := http.Get(urls[0])
					if err != nil {
						http.Error(w, "source unavailable", 502)
						return
					}
					raw, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || response.StatusCode != 200 {
						http.Error(w, "source failed", 502)
						return
					}
					if err = os.MkdirAll(dir, 0700); err == nil {
						err = os.WriteFile(filepath.Join(dir, "result.bin"), raw, 0600)
					}
					if err != nil {
						http.Error(w, "external save failed", 500)
						return
					}
					mu.Lock()
					savedDir = dir
					mu.Unlock()
				case "aria2.tellStatus":
					n := calls.Add(1)
					state := "complete"
					if (scenario == "rebound" || scenario == "revoked") && n == 1 {
						state = "active"
					}
					if (scenario == "rebound" || scenario == "revoked") && n == 2 {
						close(paused)
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
					}
					if scenario == "external_error" {
						state = "error"
					}
					mu.Lock()
					dir := savedDir
					mu.Unlock()
					size := strconv.Itoa(len(payload))
					result = map[string]any{"gid": "fixture-gid", "status": state, "dir": dir, "totalLength": size, "completedLength": size, "errorMessage": "controlled external download failure", "files": []any{map[string]any{"index": "1", "path": filepath.Join(dir, "result.bin"), "length": size, "completedLength": size, "selected": "true"}}}
				case "aria2.remove":
				default:
					http.Error(w, "unsupported external RPC", 400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			}))
			defer func() { unblock(); rpc.Close() }()

			master, err := f.db.Node.Get(context.Background(), 1)
			require.NoError(t, err)
			boolset.Set(int(types.NodeCapabilityRemoteDownload), true, master.Capabilities)
			_, err = f.db.Node.UpdateOne(master).SetCapabilities(master.Capabilities).SetSettings(&types.NodeSetting{Provider: types.DownloaderProviderAria2, Aria2Setting: &types.Aria2Setting{Server: rpc.URL, TempPath: downloadTempRoot}, Interval: 1, URLValidation: &types.URLValidationSetting{AllowedHosts: []string{"127.0.0.1"}}}).Save(context.Background())
			require.NoError(t, err)
			_, err = f.db.Setting.Create().SetName("queue_remote_download_max_retry").SetValue("0").Save(context.Background())
			require.NoError(t, err)
			aSettings := *f.policies[0].Settings
			aSettings.FileType = []string{"txt"}
			_, err = f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetMaxSize(1).SetSettings(&aSettings).Save(context.Background())
			require.NoError(t, err)
			if scenario == "size" {
				_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetMaxSize(1).Save(context.Background())
				require.NoError(t, err)
			}
			if scenario == "suffix" {
				bSettings := *f.policies[1].Settings
				bSettings.FileType = []string{"txt"}
				_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetSettings(&bSettings).Save(context.Background())
				require.NoError(t, err)
			}
			var before fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &before)
			var accepted []explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/download", map[string]any{"src": []string{source.URL + "/result.bin"}, "dst": folder}, &accepted)
			require.Len(t, accepted, 1)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			if scenario == "rebound" || scenario == "revoked" {
				select {
				case <-paused:
				case <-time.After(50 * time.Second):
					t.Fatal("external download did not reach validated monitoring boundary")
				}
				if scenario == "rebound" {
					f.bindFolder(t, folder, 0)
				} else {
					f.assignPolicies(t, f.policies[0].ID)
				}
				unblock()
			}
			status := "error"
			if scenario == "success" || scenario == "rebound" {
				status = "completed"
			}
			f.waitForStorageTaskCategory(t, accepted[0].ID, status, "downloaded")
			var after fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &after)
			if status == "completed" {
				uri := folder + "/result.bin"
				require.Equal(t, payload, f.readFile(t, uri))
				info := f.fileInfo(t, uri)
				require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), info.ExtendedInfo.Entities[0].StoragePolicy.ID)
				require.EqualValues(t, before.Used+int64(len(payload)), after.Used)
				f.assertObjectCounts(t, 1, 1)
			} else {
				require.Equal(t, before, after)
				f.assertObjectCounts(t, 1, 0)
			}
		})
	}
}
