package controllers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRealBrowserTwoBucketWorkflow(t *testing.T) {
	if os.Getenv("CLOUDREVE_STORAGE_BROWSER") != "1" {
		t.Skip("opt in production browser/native HTTP/S3 workflow")
	}
	f := newStorageFixtureWithLegacy(t, true)
	f.enableMigration(t, true)
	require.NoError(t, f.db.Group.UpdateOneID(2).SetSettings(&types.GroupSetting{MaxWalkedFiles: 10000, TrashRetention: 60}).Exec(context.Background()))
	// Directory is created through the public native API; the browser configures
	// actual group grants, binds it and uploads/migrates its own test content.
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/browser-bound", "type": "folder"}, nil)
	f.recycling = true
	worker := launchStorageWorkerWithWorkflows(t, f)
	backend := worker.ready(t)
	require.NoError(t, f.db.Setting.Update().Where(setting.Name("siteURL")).SetValue("http://127.0.0.1:43181").Exec(context.Background()))
	before := f.runStorageBrowser(t, backend, "configures", "")
	f.remote = backend
	f.login(t)
	uri := "cloudreve://my/browser-bound/browser.txt"
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Equal(t, before.Size, after.Size)
	require.Len(t, after.ExtendedInfo.Entities, 1)
	require.Equal(t, []byte("real browser and real S3 migration"), f.readFile(t, uri))
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), after.ExtendedInfo.Entities[0].StoragePolicy.ID)
	nextURI := "cloudreve://my/browser-bound/future.txt"
	require.Equal(t, []byte("future uploads still use the bound source"), f.readFile(t, nextURI))
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), f.fileInfo(t, nextURI).ExtendedInfo.Entities[0].StoragePolicy.ID)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len("persisted object before storage extension")+len("real browser and real S3 migration")+len("future uploads still use the bound source"), capacity.Used)
	model, err := f.db.File.Query().Where(file.OwnerID(2), file.Name("browser.txt")).WithEntities().Only(context.Background())
	require.NoError(t, err)
	object, err := f.s3.GetObject(&s3.GetObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(model.Edges.Entities[0].Source)})
	require.NoError(t, err)
	stored, err := io.ReadAll(object.Body)
	require.NoError(t, err)
	require.NoError(t, object.Body.Close())
	require.Equal(t, []byte("real browser and real S3 migration"), stored)
}

func (f *storageFixture) runStorageBrowser(t *testing.T, backend, mode, permanent string) *explorer.FileResponse {
	t.Helper()
	config := map[string]any{"backend": backend, "admin_email": "storage-admin@example.com", "admin_password": f.adminPassword, "member_email": "storage@example.com", "member_password": f.password, "group_id": 2, "mode": mode, "permanent_link": permanent, "result_path": filepath.Join(t.TempDir(), "result.json"), "policies": []map[string]any{{"id": f.policies[0].ID, "encoded_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), "name": f.policies[0].Name}, {"id": f.policies[1].ID, "encoded_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), "name": f.policies[1].Name}}}
	raw, err := json.Marshal(config)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "browser.json")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	command := exec.Command("pnpm", "test", "storage-real.spec.ts", "--config=playwright.config.ts", "-g", "native browser "+mode)
	command.Dir = "../../scripts/e2e"
	command.Env = append(os.Environ(), "CLOUDREVE_STORAGE_BROWSER_CONFIG="+path)
	log, err := os.Create(filepath.Join(t.TempDir(), "browser.log"))
	require.NoError(t, err)
	command.Stdout, command.Stderr = log, log
	result := command.Run()
	require.NoError(t, log.Close())
	if result != nil {
 if raw,err:=os.ReadFile(log.Name());err==nil {t.Logf("Browser diagnostics: %s",raw)}
		t.Fatalf("production browser workflow failed: %v; diagnostics: %s", result, log.Name())
	}
	if mode == "configures" {
		raw, err := os.ReadFile(config["result_path"].(string))
		require.NoError(t, err)
		var before explorer.FileResponse
		require.NoError(t, json.Unmarshal(raw, &before))
		return &before
	}
	return nil
}

func TestStorageRealBrowserMixedTreeWorkflow(t *testing.T) {
	if os.Getenv("CLOUDREVE_STORAGE_BROWSER") != "1" {
		t.Skip("opt in native mixed-tree browser/S3 workflow")
	}
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	ctx := context.Background()
	require.NoError(t, f.db.Group.UpdateOneID(2).SetSettings(&types.GroupSetting{MaxWalkedFiles: 10000, TrashRetention: 60, SourceBatchSize: 100, RedirectedSource: true}).Exec(ctx))
	for _, uri := range []string{"cloudreve://my/tree", "cloudreve://my/tree/nested"} {
		f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
	}
	// A root-level copy and the directory containing its shared versions are
	// selected together; their overlapping entities must be moved only once.
	contents := map[string][]byte{"cloudreve://my/tree/inside.txt": []byte("inside retained version"), "cloudreve://my/tree/nested/leaf.txt": []byte("nested leaf")}
	for uri, data := range contents {
		f.upload(t, uri, data, nil)
	}
	var version explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/tree/inside.txt", "size": len("inside current version"), "entity_type": "version"}, &version)
	f.finishUpload(t, version, []byte("inside current version"))
	contents["cloudreve://my/tree/inside.txt"] = []byte("inside current version")
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/tree/inside.txt"}, "dst": "cloudreve://my/", "copy": true}, nil)
	contents["cloudreve://my/inside.txt"] = []byte("inside current version")
	before := map[string]explorer.FileResponse{}
	for uri := range contents {
		before[uri] = f.fileInfo(t, uri)
	}
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	models, err := f.db.Entity.Query().All(ctx)
	require.NoError(t, err)
	f.recycling = true
	worker := launchStorageWorkerWithWorkflows(t, f)
	backend := worker.ready(t)
	require.NoError(t, f.db.Setting.Update().Where(setting.Name("siteURL")).SetValue("http://127.0.0.1:43181").Exec(ctx))
	f.remote = backend
	f.login(t)
	var direct []explorer.DirectLinkResponse
	f.request(t, http.MethodPut, "/api/v4/file/source", map[string]any{"uris": []string{"cloudreve://my/tree/inside.txt"}}, &direct)
	require.Len(t, direct, 1)
	f.runStorageBrowser(t, backend, "mixed", direct[0].Link)
	for uri, body := range contents {
		after := f.fileInfo(t, uri)
		require.Equal(t, before[uri].ID, after.ID)
		require.Equal(t, before[uri].PrimaryEntity, after.PrimaryEntity)
		require.Equal(t, before[uri].Size, after.Size)
		require.Equal(t, len(before[uri].ExtendedInfo.Entities), len(after.ExtendedInfo.Entities))
		require.Equal(t, body, f.readFile(t, uri))
		for _, entity := range after.ExtendedInfo.Entities {
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), entity.StoragePolicy.ID)
		}
	}
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	waitStorageObjectCounts(t, f, 1, 3)
	// Every selected original locator really disappears, while existing.txt stays.
	for _, model := range models {
		if model.Source == "legacy-object" {
			continue
		}
		_, err := f.s3.HeadObject(&s3.HeadObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String(model.Source)})
		require.Error(t, err)
	}
}

func waitStorageObjectCounts(t *testing.T, f *storageFixture, a, b int) {
	t.Helper()
	require.Eventually(t, func() bool {
		first, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(f.policies[0].BucketName)})
		if err != nil {
			return false
		}
		second, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(f.policies[1].BucketName)})
		return err == nil && len(first.Contents) == a && len(second.Contents) == b
	}, 45*time.Second, 100*time.Millisecond, "real S3 source cleanup and destination counts")
}
