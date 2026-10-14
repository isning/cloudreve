package controllers_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationUsesGenericLocalDestination(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	folder := t.TempDir()
	local, err := f.db.StoragePolicy.Create().SetName("Owned local destination").SetType("local").SetDirNameRule(filepath.Join(folder, "objects")).SetFileNameRule("{randomkey16}_{originname}").SetSettings(f.policies[0].Settings).Save(context.Background())
	require.NoError(t, err)
	f.assignPolicies(t, f.policies[0].ID, local.ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/generic.bin"
	data := bytes.Repeat([]byte("generic raw transfer\n"), 321)
	f.upload(t, uri, data, nil)
	before := f.fileInfo(t, uri)
	f.fillMigrationQuota(t)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), local.ID)}, &accepted)
	f.recycling = true
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	require.NoError(t, f.db.Setting.Update().Where(setting.Name("siteURL")).SetValue(f.remote).Exec(context.Background()))
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Equal(t, before.UpdatedAt, after.UpdatedAt)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), local.ID), after.ExtendedInfo.Entities[0].StoragePolicy.ID)
	sourceID, err := f.dep.HashIDEncoder().Decode(after.PrimaryEntity, hashid.EntityID)
	require.NoError(t, err)
	model, err := f.db.Entity.Get(context.Background(), sourceID)
	require.NoError(t, err)
	stored, err := os.ReadFile(model.Source)
	require.NoError(t, err)
	require.Equal(t, data, stored)
	require.Equal(t, data, f.readFile(t, uri))
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore, capacityAfter)
	require.Eventually(t, func() bool {
		item, err := f.db.RelocationItem.Query().Only(context.Background())
		return err == nil && item.SourceCleanup == relocationitem.SourceCleanupCleaned
	}, 30*time.Second, 50*time.Millisecond)
	f.assertObjectCounts(t, 1, 0)
}

func TestStorageRelocationAutomaticallyRecoversProviderCredentials(t *testing.T) {
	for _, phase := range []string{"source_copy", "destination_copy", "destination_verify", "exhausted"} {
		t.Run(phase, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			uri := "cloudreve://my/credential.txt"
			data := []byte("credential repair preserves the same destination and original identity")
			f.upload(t, uri, data, nil)
			before := f.fileInfo(t, uri)
			var capacityBefore fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
			for name, value := range map[string]string{"queue_io_intense_max_retry": "3", "queue_io_intense_retry_delay": "2"} {
				require.NoError(t, f.db.Setting.Create().SetName(name).SetValue(value).Exec(context.Background()))
			}
			faultPhase := phase
			if phase == "exhausted" {
				faultPhase = "destination_copy"
				require.NoError(t, f.db.Setting.Update().Where(setting.Name("queue_io_intense_max_retry")).SetValue("1").Exec(context.Background()))
			}
			index := 1
			if faultPhase == "source_copy" {
				index = 0
			}
			backend, err := url.Parse(f.policies[index].Server)
			require.NoError(t, err)
			proxy := httputil.NewSingleHostReverseProxy(backend)
			var denied atomic.Bool
			denied.Store(true)
			var deniedCalls atomic.Int32
			secret := storageRandom(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				match := faultPhase == "source_copy" && r.Method == http.MethodGet || faultPhase == "destination_copy" && r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") || faultPhase == "destination_verify" && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/.cloudreve-relocation/")
				if denied.Load() && match {
					deniedCalls.Add(1)
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprintf(w, "<Error><Code>AccessDenied</Code><Message>temporary credential failure secret=%s</Message></Error>", secret)
					return
				}
				proxy.ServeHTTP(w, r)
			}))
			defer server.Close()
			update := f.db.StoragePolicy.UpdateOneID(f.policies[index].ID).SetServer(server.URL)
			if phase != "destination_verify" {
				update.SetSecretKey(storageRandom(t))
			}
			require.NoError(t, update.Exec(context.Background()))
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			var retry explorer.TaskResponse
			require.Eventually(t, func() bool {
				var list explorer.TaskListResponse
				f.request(t, http.MethodGet, "/api/v4/workflow?category=general&page_size=100", nil, &list)
				for _, job := range list.Tasks {
					if job.ID == accepted.ID && job.Status == "suspending" && job.RetryCount > 0 {
						retry = job
						return true
					}
				}
				return false
			}, 40*time.Second, 50*time.Millisecond)
			require.Positive(t, deniedCalls.Load())
			require.NotEmpty(t, retry.ErrorHistory)
			require.NotContains(t, retry.ErrorHistory[0], secret)
			if phase == "exhausted" {
				failed := f.waitForStorageTask(t, accepted.ID, "error")
				require.Equal(t, 1, failed.RetryCount)
				require.Equal(t, data, f.readFile(t, uri))
				after := f.fileInfo(t, uri)
				require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
				var capacityAfter fs.Capacity
				f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
				require.Equal(t, capacityBefore, capacityAfter)
				f.assertObjectCounts(t, 2, 0)
				return
			}
			// This external credential/ACL boundary is restored by the operator; the
			// real native queue retries without a public manual-retry control or fallback.
			denied.Store(false)
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			endpoint := fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[index].ID)
			var original ent.StoragePolicy
			f.request(t, http.MethodGet, endpoint, nil, &original)
			original.SecretKey = f.policies[index].SecretKey
			f.request(t, http.MethodPut, endpoint, map[string]any{"policy": original}, nil)
			f.login(t)
			completed := f.waitForStorageTask(t, accepted.ID, "completed")
			require.Positive(t, completed.RetryCount)
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
			require.Len(t, after.ExtendedInfo.Entities, 1)
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), after.ExtendedInfo.Entities[0].StoragePolicy.ID)
			require.Equal(t, data, f.readFile(t, uri))
			var capacityAfter fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
			require.Equal(t, capacityBefore, capacityAfter)
			log, err := os.ReadFile(w.file + ".log")
			require.NoError(t, err)
			for _, private := range []string{secret, f.policies[0].SecretKey, f.policies[1].SecretKey, "X-Amz-Signature=", f.token} {
				require.NotContains(t, string(log), private)
			}
			require.Contains(t, string(log), "Cid:")
		})
	}
}
