package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationRedactsProviderFailuresAndRecoveryDiagnostics(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	_, err := f.db.Setting.Create().SetName("queue_io_intense_max_retry").SetValue("0").Save(context.Background())
	require.NoError(t, err)
	uri := "cloudreve://my/redacted.txt"
	f.upload(t, uri, []byte("safe public diagnostics"), nil)
	before := f.fileInfo(t, uri)
	entityID, err := f.dep.HashIDEncoder().Decode(before.PrimaryEntity, hashid.EntityID)
	require.NoError(t, err)
	source, err := f.db.Entity.Get(context.Background(), entityID)
	require.NoError(t, err)
	secret, signature := storageRandom(t), storageRandom(t)
	message := "secret_key=" + secret + " access_key=" + f.policies[1].AccessKey + " storage_secret=" + f.policies[1].SecretKey + " https://idp.invalid/object?X-Amz-Signature=" + signature + "&X-Amz-Credential=" + f.policies[1].AccessKey
	var encoded bytes.Buffer
	require.NoError(t, xml.EscapeText(&encoded, []byte(message)))
	backend, err := url.Parse(f.policies[1].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>"+encoded.String()+"</Message></Error>")
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Exec(context.Background()))
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	firstFailure := f.waitForStorageTask(t, accepted.ID, "error")
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	model, err := f.db.Task.Get(context.Background(), id)
	require.NoError(t, err)
	attempt, err := f.db.RelocationAttempt.Query().Only(context.Background())
	require.NoError(t, err)
	private := []string{secret, signature, f.policies[1].AccessKey, f.policies[1].SecretKey, f.token, source.Source, attempt.TargetKey}
	checkPublic := func() {
		t.Helper()
		var list, progress json.RawMessage
		f.request(t, http.MethodGet, "/api/v4/workflow?category=general&page_size=100", nil, &list)
		f.request(t, http.MethodGet, "/api/v4/workflow/progress/"+accepted.ID, nil, &progress)
		for _, raw := range [][]byte{list, progress} {
			for _, value := range private {
				require.False(t, bytes.Contains(raw, []byte(value)), "private fixture value leaked into public migration response")
			}
			for _, field := range []string{"private_state", "target_key", "source_key", "verified_digest", "lease_owner"} {
				require.False(t, bytes.Contains(raw, []byte(field)), "internal migration field leaked into public response")
			}
		}
	}
	checkLog := func(file string) {
		t.Helper()
		raw, err := os.ReadFile(file + ".log")
		require.NoError(t, err)
		for _, value := range private {
			require.False(t, bytes.Contains(raw, []byte(value)), "private fixture value leaked into migration diagnostics")
		}
		require.True(t, bytes.Contains(raw, []byte(model.CorrelationID.String())), "diagnostics retain task correlation identity")
	}
	checkPublic()
	worker.stop(t)
	checkLog(worker.file)
	// Seed the native persisted retry-history envelope with the actual first
	// failure emitted by this worker, then redeliver the command. This verifies
	// history serialization without claiming an automatic retry for a 403.
	state := *model.PublicState
	state.ErrorHistory = []string{firstFailure.Error}
	state.RetryCount = 1
	require.NoError(t, f.db.Task.UpdateOneID(id).SetPublicState(&state).SetStatus(task.StatusProcessing).Exec(context.Background()))
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	failed := f.waitForStorageTask(t, accepted.ID, "error")
	require.NotEmpty(t, failed.Error)
	require.NotEmpty(t, failed.ErrorHistory)
	checkPublic()
	restarted.stop(t)
	checkLog(restarted.file)
}
