package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	usersvc "github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/stretchr/testify/require"
)

// A worker owns its dependency graph, connection pool and caches. Only the
// operator-owned database and storage service are shared with the parent.
func TestStorageStartupWorker(t *testing.T) {
	file := os.Getenv("CLOUDREVE_STORAGE_PROCESS_CONFIG")
	if file == "" {
		t.Skip("independent storage worker")
	}
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	var database conf.Database
	require.NoError(t, json.Unmarshal(raw, &database))
	l := logging.NewConsoleLogger(logging.LevelError)
	cfg, err := conf.NewIniConfigProvider(file+".ini", l)
	require.NoError(t, err)
	*cfg.Database() = database
	cfg.System().Debug = false
	encoder, err := hashid.New("storage-http-fixture")
	require.NoError(t, err)
	d := dependency.NewDependency(dependency.WithConfigProvider(cfg), dependency.WithLogger(l), dependency.WithKV(cache.NewMemoStore("", l)),
		dependency.WithHashIDEncoder(encoder), dependency.WithRequiredDbVersion("4.14.0"))
	defer d.DBClient().Close()

	defer d.Shutdown(context.Background())
	if os.Getenv("CLOUDREVE_STORAGE_RUN_WORKFLOWS") == "1" {
		d.IoIntenseQueue(context.Background()).Start()
		d.ThumbQueue(context.Background()).Start()
		d.RemoteDownloadQueue(context.Background()).Start()
	}
	if os.Getenv("CLOUDREVE_STORAGE_RUN_RECYCLING") == "1" {
		d.EntityRecycleQueue(context.Background()).Start()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: storageRouter(d, l), ReadHeaderTimeout: 5 * time.Second}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt)
	defer signal.Stop(stopped)
	go server.Serve(listener)
	require.NoError(t, os.WriteFile(file+".ready", []byte("http://"+listener.Addr().String()), 0600))
	<-stopped
	require.NoError(t, server.Close())
}

type storageWorker struct {
	cmd      *exec.Cmd
	file     string
	done     chan error
	stopOnce sync.Once
}

func launchStorageWorker(t *testing.T, f *storageFixture) *storageWorker {
	return launchStorageWorkerMode(t, f, false)
}

func launchStorageWorkerWithWorkflows(t *testing.T, f *storageFixture) *storageWorker {
	return launchStorageWorkerMode(t, f, true)
}

func launchStorageWorkerMode(t *testing.T, f *storageFixture, workflows bool) *storageWorker {
	t.Helper()
	file := filepath.Join(t.TempDir(), "storage-worker.json")
	raw, err := json.Marshal(f.database)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, raw, 0600))
	log, err := os.Create(file + ".log")
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=^TestStorageStartupWorker$", "-test.timeout=180s")
	cmd.Env = append(os.Environ(), "CLOUDREVE_STORAGE_PROCESS_CONFIG="+file)
	if workflows {
		cmd.Env = append(cmd.Env, "CLOUDREVE_STORAGE_RUN_WORKFLOWS=1")
	}
	if f.recycling {
		cmd.Env = append(cmd.Env, "CLOUDREVE_STORAGE_RUN_RECYCLING=1")
	}
	cmd.Stdout, cmd.Stderr = log, log
	require.NoError(t, cmd.Start())
	w := &storageWorker{cmd: cmd, file: file, done: make(chan error, 1)}
	go func() { w.done <- cmd.Wait(); log.Close() }()
	t.Cleanup(func() { w.stop(t) })
	return w
}

func (w *storageWorker) stop(t *testing.T) {
	t.Helper()
	w.stopOnce.Do(func() {
		_ = w.cmd.Process.Signal(os.Interrupt)
		select {
		case <-w.done:
		case <-time.After(10 * time.Second):
			t.Error("owned storage worker did not stop")
		}
	})
}

func (w *storageWorker) ready(t *testing.T) string {
	t.Helper()
	var endpoint string
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(w.file + ".ready")
		if err != nil {
			return false
		}
		endpoint = string(b)
		return endpoint != ""
	}, 20*time.Second, 20*time.Millisecond, "storage worker did not become ready")
	return endpoint
}

func TestStorageConcurrentStartupPreservesPublicBehavior(t *testing.T) {
	f := prepareStorageFixture(t, true)
	first := launchStorageWorker(t, f)
	second := launchStorageWorker(t, f)
	for _, worker := range []*storageWorker{first, second} {

		f.remote = worker.ready(t)
		f.login(t)
		f.oidcLogin(t)
		var policies []explorer.StoragePolicy
		f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
		require.Len(t, policies, 1)
		var preferences usersvc.UserSettings
		f.request(t, http.MethodGet, "/api/v4/user/setting", nil, &preferences)
		require.Len(t, preferences.OpenID, 1)
		// Startup must add both durable journal tables independently of the
		// already-installed upstream and OIDC markers.
		_, err := f.db.RelocationItem.Query().Count(context.Background())
		require.NoError(t, err)
		_, err = f.db.RelocationAttempt.Query().Count(context.Background())
		require.NoError(t, err)
		marker, err := f.db.Setting.Query().Where(setting.Name(inventory.StorageSchemaVersion)).Only(context.Background())
		require.NoError(t, err)
		require.Equal(t, "complete", marker.Value)
	}
	f.remote = first.ready(t)
	f.login(t)
	f.upload(t, "cloudreve://my/concurrent-start.txt", []byte("upload after two independent initializers"), nil)
	first.stop(t)
	second.stop(t)
	restarted := launchStorageWorker(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{"cloudreve://my/concurrent-start.txt"}}, &links)
	_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	require.Equal(t, "upload after two independent initializers", string(data))
}

func (f *storageFixture) oidcLogin(t *testing.T) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	request := func(method string, body any, result any) {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		req, err := http.NewRequest(method, f.remote+"/api/v4/session/openid", bytes.NewReader(raw))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		require.True(t, err == nil, "native OIDC HTTP transport failed")
		defer res.Body.Close()
		var envelope struct {
			Code int
			Data json.RawMessage
			Msg  string
		}
		require.NoError(t, json.NewDecoder(res.Body).Decode(&envelope))
		require.Zero(t, envelope.Code, "native OIDC sign-in failed: %s", auth.RedactSensitiveValues(envelope.Msg))
		require.NoError(t, json.Unmarshal(envelope.Data, result))
	}
	var authorization string
	request(http.MethodPut, map[string]int{"provider": 3}, &authorization)
	target, err := url.Parse(authorization)
	require.NoError(t, err)
	var login usersvc.BuiltinLoginResponse
	request(http.MethodPost, map[string]any{"provider_id": 3, "session_id": target.Query().Get("state"), "code": f.idp.code(t, authorization)}, &login)
	f.token = login.Token.AccessToken
	require.NotEmpty(t, f.token)
}

func TestStoragePartialInitializationRecoversAfterRestart(t *testing.T) {
	f := prepareStorageFixture(t, true)
	partial := *entmigrate.GroupPoliciesTable
	partial.Indexes = nil
	require.NoError(t, entmigrate.Create(context.Background(), f.db.Schema, []*schema.Table{&partial}, schema.WithAtlas(false)))
	for _, policy := range f.policies {
		_, err := f.db.GroupPolicy.Create().SetGroupID(2).SetStoragePolicyID(policy.ID).SetPosition(0).Save(context.Background())
		require.NoError(t, err)
	}
	failed := launchStorageWorker(t, f)
	select {
	case err := <-failed.done:
		require.Error(t, err, "invalid partial authorization schema must prevent startup")
		failed.done <- err
	case <-time.After(20 * time.Second):
		t.Fatal("partial initialization did not fail promptly")
	}
	// Repair the operator-owned partial fixture; verification remains at HTTP.
	require.NoError(t, f.db.GroupPolicy.Update().Where(grouppolicy.StoragePolicyID(f.policies[1].ID)).SetPosition(1).Exec(context.Background()))
	recovered := launchStorageWorker(t, f)
	f.remote = recovered.ready(t)
	f.login(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, f.policies[0].Name, policies[0].Name)
	require.Equal(t, f.policies[1].Name, policies[1].Name)
	f.upload(t, "cloudreve://my/recovered.txt", []byte("resumed initialization preserves default writes"), nil)
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{"cloudreve://my/existing.txt"}}, &links)
	_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	require.Equal(t, "persisted object before storage extension", string(data))
}

func TestStoragePartialRelocationJournalUpgradeRecoversFromV2(t *testing.T) {
	f := prepareStorageFixture(t, true)
	ctx := context.Background()
	partial := *entmigrate.RelocationItemsTable
	partial.Indexes = nil
	require.NoError(t, entmigrate.Create(ctx, f.db.Schema, []*schema.Table{entmigrate.GroupPoliciesTable, &partial}, schema.WithAtlas(false)))
	_, err := f.db.Setting.Create().SetName("storage_extension_schema_v2").SetValue("complete").Save(ctx)
	require.NoError(t, err)
	var duplicateID int
	for i := 0; i < 2; i++ {
		item, err := f.db.RelocationItem.Create().SetTaskID(999).SetOwnerID(2).SetSourceEntityID(1).
			SetSourcePolicyID(f.policies[0].ID).SetSourceKey("legacy-object").SetSourceLocation("owned-fixture-location").
			SetDestinationPolicyID(f.policies[0].ID).SetDestinationLocation("owned-fixture-location").
			SetSnapshot(&types.RelocationSnapshot{Type: int(types.EntityTypeVersion), Size: 0}).SetReferences([]types.RelocationReference{}).Save(ctx)
		require.NoError(t, err)
		duplicateID = item.ID
	}
	failed := launchStorageWorker(t, f)
	select {
	case err := <-failed.done:
		require.Error(t, err, "duplicate journal identity must prevent a false successful upgrade")
		failed.done <- err
	case <-time.After(20 * time.Second):
		t.Fatal("partial journal initialization did not fail promptly")
	}
	complete, err := f.db.Setting.Query().Where(setting.Name(inventory.StorageSchemaVersion), setting.Value("complete")).Exist(ctx)
	require.NoError(t, err)
	require.False(t, complete)
	// Repair only the deliberately duplicated fixture row, which owns no I/O.
	require.NoError(t, f.db.RelocationItem.DeleteOneID(duplicateID).Exec(ctx))
	recovered := launchStorageWorkerWithWorkflows(t, f)
	f.remote = recovered.ready(t)
	f.login(t)
	f.oidcLogin(t)
	require.Equal(t, []byte("persisted object before storage extension"), f.readFile(t, "cloudreve://my/existing.txt"))
	f.enableMigration(t, true)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{"cloudreve://my/existing.txt"}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)}, &accepted)
	// Restart after accepting the command to exercise persisted native work
	// and completion rather than relying on its in-memory queue state.
	recovered.stop(t)
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	count, err := f.db.RelocationItem.Query().Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, count, "the repaired prior plan and one no-op plan survive upgrades")
	_, err = f.db.RelocationAttempt.Query().Count(ctx)
	require.NoError(t, err)
	_, err = f.db.Setting.Query().Where(setting.Name("storage_extension_schema_v2"), setting.Value("complete")).Only(ctx)
	require.NoError(t, err)
}

func TestStorageV3JournalUpgradePreservesUnknownAttempts(t *testing.T) {
	f := prepareStorageFixture(t, true)
	ctx := context.Background()
	prior := *entmigrate.RelocationAttemptsTable
	prior.Columns = nil
	for _, column := range entmigrate.RelocationAttemptsTable.Columns {
		if column.Name != "source_read_finished" && column.Name != "transferred_size" {
			prior.Columns = append(prior.Columns, column)
		}
	}
	require.NoError(t, entmigrate.Create(ctx, f.db.Schema, []*schema.Table{entmigrate.GroupPoliciesTable, entmigrate.RelocationItemsTable, &prior}, schema.WithAtlas(false)))
	_, err := f.db.Setting.Create().SetName("storage_extension_schema_v3").SetValue("complete").Save(ctx)
	require.NoError(t, err)
	item, err := f.db.RelocationItem.Create().SetTaskID(999).SetOwnerID(2).SetSourceEntityID(1).
		SetSourcePolicyID(f.policies[0].ID).SetSourceKey("legacy-object").SetSourceLocation("prior-owned-location").
		SetDestinationPolicyID(f.policies[1].ID).SetDestinationLocation("prior-owned-location").
		SetSnapshot(&types.RelocationSnapshot{Type: int(types.EntityTypeVersion)}).SetReferences([]types.RelocationReference{}).Save(ctx)
	require.NoError(t, err)
	_, err = f.db.ExecContext(ctx, "INSERT INTO relocation_attempts (created_at, updated_at, item_id, fence, target_key, io_state, verified_size, verified_digest, verified, cleanup, error) VALUES (?, ?, ?, 1, 'prior-owned-target', 'unknown', 0, '', 0, 'pending', '')", time.Now(), time.Now(), item.ID)
	require.NoError(t, err)
	w := launchStorageWorker(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.oidcLogin(t)
	require.Equal(t, []byte("persisted object before storage extension"), f.readFile(t, "cloudreve://my/existing.txt"))
	attempt, err := f.db.RelocationAttempt.Query().Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "prior-owned-target", attempt.TargetKey)
	require.Equal(t, "unknown", string(attempt.IoState))
	require.Zero(t, attempt.TransferredSize, "prior attempts gain an additive zero byte counter")
	require.False(t, attempt.SourceReadFinished, "prior unknown readers must remain conservatively unresolved")
	_, err = f.db.Setting.Query().Where(setting.Name("storage_extension_schema_v3"), setting.Value("complete")).Only(ctx)
	require.NoError(t, err)
}
