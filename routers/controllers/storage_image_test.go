package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

// Executes the actual packaged main application and router, not a test worker.
func TestStorageRuntimeImageWorkflow(t *testing.T) {
	image := os.Getenv("CLOUDREVE_STORAGE_IMAGE")
	if image == "" {
		t.Skip("provide a locally built runtime image")
	}
	engine := os.Getenv("CLOUDREVE_CONTAINER_ENGINE")
	if engine == "" {
		engine = "docker"
	}
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	ctx := context.Background()
	base := fmt.Sprintf("http://127.0.0.1:%d", storagePort(t))
	require.NoError(t, f.db.Setting.Update().Where(setting.Name("siteURL")).SetValue(base).Exec(ctx))
	workspace, err := filepath.Abs("../..")
	require.NoError(t, err)
	root := filepath.Dir(filepath.Dir(f.database.DBFile))
	config := filepath.Join(t.TempDir(), "image.ini")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf("[System]\nMode=master\nListen=%s\n[Database]\nType=sqlite3\nDBFile=%s\n", strings.TrimPrefix(base, "http://"), f.database.DBFile)), 0600))
	name := "cloudreve-storage-image-" + storageRandom(t)[:12]
	log, err := os.Create(filepath.Join(t.TempDir(), "image.log"))
	require.NoError(t, err)
	command := exec.Command(engine, "run", "--name", name, "--label", "io.cloudreve.workspace="+workspace, "--network", "host", "--volume", root+":"+root, "--entrypoint", "/cloudreve/cloudreve", image, "-c", config)
	command.Stdout, command.Stderr = log, log
	require.NoError(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait(); log.Close(); close(done) }()
	t.Cleanup(func() {
		require.NoError(t, exec.Command(engine, "stop", name).Run())
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("owned image did not stop")
		}
	})
	deadline := time.Now().Add(120 * time.Second)
	for {
		response, err := http.Get(base + "/api/v4/site/ping")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case result := <-done:
			t.Fatalf("runtime image exited before readiness: %v; %s", result, log.Name())
		default:
		}
		require.True(t, time.Now().Before(deadline), "runtime image readiness timeout; inspect %s", log.Name())
		time.Sleep(200 * time.Millisecond)
	}
	f.remote = base
	f.token = ""
	f.login(t)
	response, err := http.Get(base + "/")
	require.NoError(t, err)
	markup, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	response.Body.Close()
	require.Contains(t, strings.ToLower(string(markup)), "<html")
	var descriptors []map[string]any
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &descriptors)
	require.Len(t, descriptors, 2)
	uri := "cloudreve://my/runtime-image.txt"
	content := []byte("packaged native HTTP real S3 upload and relocation")
	f.upload(t, uri, content, nil)
	before := f.fileInfo(t, uri)
	var usageBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &usageBefore)
	var task explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": descriptors[1]["id"]}, &task)
	f.waitForStorageTask(t, task.ID, "completed")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Equal(t, descriptors[1]["id"], after.ExtendedInfo.Entities[0].StoragePolicy.ID)
	require.Equal(t, content, f.readFile(t, uri))
	var usageAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &usageAfter)
	require.Equal(t, usageBefore.Used, usageAfter.Used)
	model, err := f.db.File.Query().Where(file.Name("runtime-image.txt")).WithEntities().Only(ctx)
	require.NoError(t, err)
	object, err := f.s3.GetObject(&s3.GetObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(model.Edges.Entities[0].Source)})
	require.NoError(t, err)
	raw, err := io.ReadAll(object.Body)
	require.NoError(t, err)
	object.Body.Close()
	require.Equal(t, content, raw)
	// The image's embedded frontend has a real matching build manifest.
	response, err = http.Get(base + "/version.json")
	require.NoError(t, err)
	defer response.Body.Close()
	var manifest map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&manifest))
	require.Equal(t, "cloudreve-frontend", manifest["name"])
}
