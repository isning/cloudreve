package controllers_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/workflows"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/cloudreve/Cloudreve/v4/routers"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func auditWorkflowContext(t *testing.T, f *storageFixture) context.Context {
	t.Helper()
	ctx := f.dep.ForkWithLogger(context.Background(), f.dep.Logger())
	actor, err := f.dep.UserClient().GetActiveByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), 2)
	require.NoError(t, err)
	return context.WithValue(ctx, inventory.UserCtx{}, actor)
}

func TestAuditArchiveCompletionOutageRetainsRecoveryWithoutReupload(t *testing.T) {
	f := newAuditFixture(t)
	f.enableArchive(t)
	f.login(t)
	src, dst := "cloudreve://my/completion-source.txt", "cloudreve://my/completion.zip"
	f.upload(t, src, []byte("archive completion must survive an audit outage"), nil)
	source := f.fileInfo(t, src)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	var failing atomic.Bool
	failing.Store(true)
	attempted := make(chan struct{}, 1)
	f.db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, mutation entgo.Mutation) (entgo.Value, error) {
			kind, _ := mutation.Field("type")
			if kind == int(types.AuditCreateArchive) && failing.Load() {
				select {
				case attempted <- struct{}{}:
				default:
				}
				return nil, errors.New("injected archive completion audit outage")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	worker := queue.New(f.dep.Logger(), f.dep.TaskClient(), f.dep.TaskRegistry(), f.dep,
		queue.WithResumeTaskType(queue.CreateArchiveTaskType), queue.WithWorkerCount(1),
		queue.WithTaskPullInterval(10*time.Millisecond), queue.WithRetryDelay(10*time.Millisecond))
	t.Cleanup(worker.Shutdown)
	worker.Start()
	select {
	case <-attempted:
	case <-time.After(15 * time.Second):
		t.Fatal("native archive worker did not reach completion persistence")
	}
	f.waitForStorageTask(t, accepted.ID, "processing")
	pending, err := f.db.Task.Get(context.Background(), id)
	require.NoError(t, err)
	var state workflows.CreateArchiveTaskState
	require.NoError(t, json.Unmarshal([]byte(pending.PrivateState), &state))
	archivePath := filepath.Join(state.TempPath, state.ArchiveFile)
	require.FileExists(t, archivePath)
	_, registered := f.dep.TaskRegistry().Get(id)
	require.True(t, registered)
	require.Zero(t, worker.SuccessTasks())
	before := f.fileInfo(t, dst)
	archive := f.readFile(t, dst)
	failing.Store(false)
	f.waitForStorageTask(t, accepted.ID, "completed")
	worker.Shutdown()
	require.EqualValues(t, 1, worker.SuccessTasks())
	require.NoDirExists(t, state.TempPath)
	after := f.fileInfo(t, dst)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity, "completion retries must not upload a second version")
	require.Equal(t, archive, f.readFile(t, dst))
	assertAuditFileEvent(t, f, source.ID, types.AuditCreateArchive, 1)
}

func TestAuditRelocationCommitsWithItsJournal(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.router = routers.InitRouter(f.dep)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableMigration(t, true)
	f.login(t)
	uri, data := "cloudreve://my/audit-relocate.txt", []byte("journal and audit share one transaction")
	f.upload(t, uri, data, nil)
	before := f.fileInfo(t, uri)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{
		"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID),
	}, &accepted)
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	require.Equal(t, data, f.readFile(t, uri))
	worker.stop(t)
	f.remote = ""
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var logs struct {
		Logs []struct {
			FileID int `json:"file_id"`
			UserID int `json:"user_id"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{
		"page": 1, "page_size": 20, "conditions": map[string]string{"audit_log_category": "27"},
	}, &logs)
	require.Len(t, logs.Logs, 1)
	require.Equal(t, before.ID, hashid.EncodeFileID(f.dep.HashIDEncoder(), logs.Logs[0].FileID))
	require.Equal(t, 2, logs.Logs[0].UserID)
}

func TestAuditArchiveRetainsConsumedSourceAfterRenameAndPathReuse(t *testing.T) {
	f := newAuditFixture(t)
	f.enableArchive(t)
	f.login(t)
	src, dst := "cloudreve://my/original-source.txt", "cloudreve://my/identity.zip"
	data := []byte("contents of the original archived file")
	f.upload(t, src, data, nil)
	original := f.fileInfo(t, src)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	ctx := auditWorkflowContext(t, f)
	client := f.dep.TaskClient()
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	model, err := client.GetTaskByID(ctx, id)
	require.NoError(t, err)
	job := workflows.NewCreateArchiveTaskFromModel(model).(*workflows.CreateArchiveTask)
	defer func() { require.NoError(t, job.Cleanup(ctx)) }()
	for range 2 {
		status, err := job.Do(ctx)
		require.NoError(t, err)
		require.Equal(t, task.StatusSuspending, status)
		_, err = client.Update(ctx, job.Model(), &inventory.TaskArgs{Status: status, PrivateState: job.State(), PublicState: &types.TaskPublicState{}})
		require.NoError(t, err)
	}
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": src, "new_name": "renamed-original.txt"}, nil)
	f.upload(t, src, []byte("unrelated replacement contents"), nil)
	replacement := f.fileInfo(t, src)
	require.NotEqual(t, original.ID, replacement.ID)
	// Resume from durable state after the original path has been reused.
	model, err = client.GetTaskByID(ctx, id)
	require.NoError(t, err)
	job = workflows.NewCreateArchiveTaskFromModel(model).(*workflows.CreateArchiveTask)
	status, err := job.Do(ctx)
	require.NoError(t, err)
	require.Equal(t, task.StatusCompleted, status)
	archive := f.readFile(t, dst)
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)
	require.Len(t, zr.File, 1)
	entry, err := zr.File[0].Open()
	require.NoError(t, err)
	actual, err := io.ReadAll(entry)
	require.NoError(t, err)
	require.NoError(t, entry.Close())
	require.Equal(t, data, actual)
	events := job.CompletionAudit(ctx)
	require.Len(t, events, 1)
	require.Equal(t, original.ID, hashid.EncodeFileID(f.dep.HashIDEncoder(), events[0].FileID))
	_, err = client.Update(ctx, job.Model(), &inventory.TaskArgs{Status: status, PrivateState: job.State(), PublicState: &types.TaskPublicState{}, AuditEvents: events, PreserveCompleted: true})
	require.NoError(t, err)
	assertAuditFileEvent(t, f, original.ID, types.AuditCreateArchive, 1)
	assertAuditFileEvent(t, f, replacement.ID, types.AuditCreateArchive, 0)
}

func assertAuditFileEvent(t *testing.T, f *storageFixture, fileID string, kind types.AuditEvent, count int) {
	t.Helper()
	previous := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	defer func() { f.token = previous }()
	var result struct {
		Logs []*ent.AuditLog `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{
		"page": 1, "page_size": 20, "conditions": map[string]string{"audit_log_file": fileID},
	}, &result)
	found := 0
	for _, row := range result.Logs {
		if row.Type == int(kind) {
			found++
		}
	}
	require.Equal(t, count, found)
}

func TestAuditExtractRetainsDownloadedSourceAfterPathReuse(t *testing.T) {
	f := newAuditFixture(t)
	f.enableArchive(t)
	f.login(t)
	src, dst := "cloudreve://my/input.zip", "cloudreve://my/extracted"
	data := []byte("contents of the original downloaded archive")
	f.upload(t, src, storageZip(t, map[string][]byte{"original.txt": data}), nil)
	original := f.fileInfo(t, src)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": dst, "type": "folder"}, nil)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/extract", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	ctx := auditWorkflowContext(t, f)
	client := f.dep.TaskClient()
	id, err := f.dep.HashIDEncoder().Decode(accepted.ID, hashid.TaskID)
	require.NoError(t, err)
	model, err := client.GetTaskByID(ctx, id)
	require.NoError(t, err)
	job := workflows.NewExtractArchiveTaskFromModel(model).(*workflows.ExtractArchiveTask)
	defer func() { require.NoError(t, job.Cleanup(ctx)) }()
	// The native S3 ZIP workflow first identifies, then downloads the archive.
	for range 2 {
		status, err := job.Do(ctx)
		require.NoError(t, err)
		require.Equal(t, task.StatusSuspending, status)
		_, err = client.Update(ctx, job.Model(), &inventory.TaskArgs{Status: status, PrivateState: job.State(), PublicState: &types.TaskPublicState{}})
		require.NoError(t, err)
	}
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": src, "new_name": "renamed-input.zip"}, nil)
	f.upload(t, src, storageZip(t, map[string][]byte{"replacement.txt": []byte("unrelated replacement")}), nil)
	replacement := f.fileInfo(t, src)
	model, err = client.GetTaskByID(ctx, id)
	require.NoError(t, err)
	job = workflows.NewExtractArchiveTaskFromModel(model).(*workflows.ExtractArchiveTask)
	status, err := job.Do(ctx)
	require.NoError(t, err)
	require.Equal(t, task.StatusCompleted, status)
	require.Equal(t, data, f.readFile(t, dst+"/original.txt"))
	events := job.CompletionAudit(ctx)
	require.Len(t, events, 1)
	require.Equal(t, original.ID, hashid.EncodeFileID(f.dep.HashIDEncoder(), events[0].FileID))
	_, err = client.Update(ctx, job.Model(), &inventory.TaskArgs{Status: status, PrivateState: job.State(), PublicState: &types.TaskPublicState{}, AuditEvents: events, PreserveCompleted: true})
	require.NoError(t, err)
	assertAuditFileEvent(t, f, original.ID, types.AuditExtractArchive, 1)
	assertAuditFileEvent(t, f, replacement.ID, types.AuditExtractArchive, 0)
}

func TestAuditArchiveCompletionSurvivesWorkerRestartWithoutDuplicateEvents(t *testing.T) {
	f := newAuditFixture(t)
	f.enableArchive(t)
	f.login(t)
	src, dst := "cloudreve://my/archive-source.txt", "cloudreve://my/audited.zip"
	f.upload(t, src, []byte("durable archive audit"), nil)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	worker.stop(t)
	worker = launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	worker.stop(t)
	f.remote = ""
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var result struct {
		Logs []struct {
			FileID  int `json:"file_id"`
			UserID  int `json:"user_id"`
			Content struct {
				To string `json:"to"`
			} `json:"content"`
		} `json:"logs"`
	}
	f.request(t, http.MethodPost, "/api/v4/admin/event", map[string]any{"page": 1, "page_size": 100, "conditions": map[string]string{"audit_log_category": "28"}}, &result)
	require.Len(t, result.Logs, 1)
	require.Positive(t, result.Logs[0].FileID)
	require.Equal(t, 2, result.Logs[0].UserID)
	require.Contains(t, result.Logs[0].Content.To, "audited.zip")
}
