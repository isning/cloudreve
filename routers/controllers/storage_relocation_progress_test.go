package controllers_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationReportsDurablePartialFailureAndProgress(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	// This case proves terminal partial-failure progress; temporary denial recovery
	// and retry exhaustion have their own native queue acceptance scenarios.
	require.NoError(t, f.db.Setting.Create().SetName("queue_io_intense_max_retry").SetValue("0").Exec(context.Background()))
	folder := "cloudreve://my/progress"
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
	for _, name := range []string{"first", "second", "third"} {
		f.upload(t, folder+"/"+name+".txt", []byte("progress bytes"), nil)
	}
	backend, err := url.Parse(f.policies[1].Server)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	var puts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/.cloudreve-relocation/") && puts.Add(1) == 2 {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>controlled target refusal</Message></Error>")
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	require.NoError(t, f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(server.URL).Exec(context.Background()))
	var accepted explorer.TaskResponse
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{folder}, "dst_policy_id": b}, &accepted)
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	failed := f.waitForStorageTask(t, accepted.ID, "error")
	require.Equal(t, "failed", failed.Summary.Phase)
	require.Equal(t, float64(3), failed.Summary.Props["entities_total"])
	require.Equal(t, float64(1), failed.Summary.Props["entities_completed"])
	require.Equal(t, float64(2), failed.Summary.Props["entities_failed"])
	require.Equal(t, float64(3*len("progress bytes")), failed.Summary.Props["bytes_total"])
	require.Equal(t, float64(2*len("progress bytes")), failed.Summary.Props["bytes_copied"])
	var before queue.Progresses
	f.request(t, http.MethodGet, "/api/v4/workflow/progress/"+accepted.ID, nil, &before)
	require.Equal(t, int64(3), before["relocate_count"].Total)
	require.Equal(t, int64(1), before["relocate_count"].Current)
	require.Equal(t, int64(2), before["relocate_failed"].Current)
	require.Equal(t, int64(2*len("progress bytes")), before["relocate_size"].Current)
	for _, name := range []string{"first", "second", "third"} {
		info := f.fileInfo(t, folder+"/"+name+".txt")
		expected := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
		if name == "first" {
			expected = b
		}
		require.Equal(t, expected, info.ExtendedInfo.Entities[0].StoragePolicy.ID)
		require.Equal(t, "progress bytes", string(f.readFile(t, folder+"/"+name+".txt")))
	}
	worker.stop(t)
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	require.NoError(t, f.db.Task.UpdateOneID(id).SetStatus(task.StatusProcessing).Exec(context.Background()))
	restarted := launchStorageWorkerWithWorkflows(t, f)
	f.remote = restarted.ready(t)
	f.login(t)
	after := f.waitForStorageTask(t, accepted.ID, "error")
	require.Equal(t, failed.Summary, after.Summary)
	var progress queue.Progresses
	f.request(t, http.MethodGet, "/api/v4/workflow/progress/"+accepted.ID, nil, &progress)
	require.Equal(t, before, progress)
	require.Equal(t, int32(2), puts.Load(), "recovery must not count or write committed entities twice")
}
