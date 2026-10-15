package queue

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/ent"
	_ "github.com/cloudreve/Cloudreve/v4/ent/runtime"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/audit"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

type auditedCompletionTask struct{ *DBTask }

func (*auditedCompletionTask) Do(context.Context) (task.Status, error) {
	return task.StatusCompleted, nil
}

func (*auditedCompletionTask) CompletionAudit(context.Context) []inventory.AuditEvent {
	return []inventory.AuditEvent{{Type: types.AuditCreateArchive, FileID: 42}}
}

func auditTaskFixture(t *testing.T) (context.Context, *ent.Client, *queue, *auditedCompletionTask) {
	t.Helper()
	driver, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "tasks.db"))
	require.NoError(t, err)
	driver.DB().SetMaxOpenConns(1)
	db := ent.NewClient(ent.Driver(driver))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ctx := context.Background()
	require.NoError(t, db.Schema.Create(ctx))
	settings := setting.NewProvider(setting.NewDbSettingStore(inventory.NewSettingClient(db, nil), setting.NewDbDefaultStore(nil)))
	ctx = audit.WithRecorder(ctx, audit.New(db, settings, logging.NewConsoleLogger(logging.LevelError)))
	client := inventory.NewTaskClient(db, conf.SQLiteDB, nil)
	model, err := client.New(ctx, &inventory.TaskArgs{
		Type: CreateArchiveTaskType, Status: task.StatusProcessing,
		PrivateState: "winner state", PublicState: &types.TaskPublicState{},
		CorrelationID: uuid.Must(uuid.NewV4()),
	})
	require.NoError(t, err)
	return ctx, db, &queue{taskClient: client}, &auditedCompletionTask{DBTask: &DBTask{Task: model, DirectOwner: &ent.User{}}}
}

func TestAuditedTaskPreservesCompletionAcrossStaleWorkerUpdates(t *testing.T) {
	for _, status := range []task.Status{task.StatusQueued, task.StatusProcessing, task.StatusSuspending, task.StatusError, task.StatusCanceled} {
		t.Run(string(status), func(t *testing.T) {
			ctx, db, q, winner := auditTaskFixture(t)
			staleModel := *winner.Model()
			staleModel.PrivateState = "stale state"
			stale := &auditedCompletionTask{DBTask: &DBTask{Task: &staleModel, DirectOwner: &ent.User{}}}
			require.NoError(t, saveTaskToInventory(ctx, winner, task.StatusCompleted, q))
			require.NoError(t, saveTaskToInventory(ctx, stale, status, q))
			current, err := db.Task.Get(ctx, winner.ID())
			require.NoError(t, err)
			require.Equal(t, task.StatusCompleted, current.Status)
			require.Equal(t, "winner state", current.PrivateState)
			require.NoError(t, saveTaskToInventory(ctx, stale, task.StatusCompleted, q))
			require.Equal(t, 1, db.AuditLog.Query().CountX(ctx), "one durable completion produces one event")
		})
	}
}

func TestAuditedTaskCompletionRollsBackWhenItsRecordFails(t *testing.T) {
	ctx, db, q, job := auditTaskFixture(t)
	fail := true
	db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, mutation entgo.Mutation) (entgo.Value, error) {
			if fail {
				return nil, errors.New("injected audit failure")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	require.Error(t, saveTaskToInventory(ctx, job, task.StatusCompleted, q))
	require.Equal(t, task.StatusProcessing, db.Task.GetX(ctx, job.ID()).Status)
	require.Zero(t, db.AuditLog.Query().CountX(ctx))
	fail = false
	require.NoError(t, saveTaskToInventory(ctx, job, task.StatusCompleted, q))
	require.Equal(t, task.StatusCompleted, db.Task.GetX(ctx, job.ID()).Status)
	require.Equal(t, 1, db.AuditLog.Query().CountX(ctx))
}

type auditQueueDependency struct{ recorder *audit.Recorder }

func (d auditQueueDependency) ForkWithLogger(ctx context.Context, _ logging.Logger) context.Context {
	return audit.WithRecorder(ctx, d.recorder)
}

type recoveringAuditedTask struct {
	*auditedCompletionTask
	path         string
	executions   atomic.Int32
	cleanups     atomic.Int32
	checkCleanup func()
}

func (t *recoveringAuditedTask) Do(context.Context) (task.Status, error) {
	t.executions.Add(1)
	_, err := os.Stat(t.path)
	return task.StatusCompleted, err
}

func (t *recoveringAuditedTask) Cleanup(context.Context) error {
	t.cleanups.Add(1)
	if t.checkCleanup != nil {
		t.checkCleanup()
	}
	return os.Remove(t.path)
}

func recoveringQueue(t *testing.T, ctx context.Context, client inventory.TaskClient, model *ent.Task, path string) (*queue, *recoveringAuditedTask) {
	t.Helper()
	job := &recoveringAuditedTask{auditedCompletionTask: &auditedCompletionTask{DBTask: &DBTask{Task: model, DirectOwner: &ent.User{}}}, path: path}
	registry := NewTaskRegistry()
	registry.Set(job.ID(), job)
	q := New(logging.NewConsoleLogger(logging.LevelError), client, registry,
		auditQueueDependency{audit.FromContext(ctx)}, WithRetryDelay(time.Millisecond)).(*queue)
	t.Cleanup(q.Shutdown)
	return q, job
}

func TestAuditedQueueRetriesCompletionWithoutRepeatingWorkOrPrematureCleanup(t *testing.T) {
	ctx, db, fixture, model := auditTaskFixture(t)
	path := filepath.Join(t.TempDir(), "archive.zip")
	require.NoError(t, os.WriteFile(path, []byte("completed archive"), 0600))
	model.Task.PrivateState = path
	q, job := recoveringQueue(t, ctx, fixture.taskClient, model.Model(), path)
	var attempts int
	var prematureCleanup bool
	db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, mutation entgo.Mutation) (entgo.Value, error) {
			attempts++
			if attempts <= 2 {
				_, err := os.Stat(path)
				_, registered := q.registry.Get(job.ID())
				prematureCleanup = prematureCleanup || err != nil || !registered || q.SuccessTasks() != 0
				return nil, errors.New("transient completion audit outage")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	var statusAtCleanup task.Status
	var eventsAtCleanup int
	job.checkCleanup = func() {
		statusAtCleanup = db.Task.GetX(ctx, job.ID()).Status
		eventsAtCleanup = db.AuditLog.Query().CountX(ctx)
	}
	q.metric.IncBusyWorker()
	q.work(job)
	require.Equal(t, task.StatusCompleted, db.Task.GetX(ctx, job.ID()).Status)
	require.Equal(t, 3, attempts)
	require.False(t, prematureCleanup)
	require.EqualValues(t, 1, job.executions.Load(), "persistence retries must not execute the workflow again")
	require.EqualValues(t, 1, job.cleanups.Load())
	require.Equal(t, task.StatusCompleted, statusAtCleanup)
	require.Equal(t, 1, eventsAtCleanup)
	require.EqualValues(t, 1, q.SuccessTasks())
	require.Equal(t, 1, db.AuditLog.Query().CountX(ctx))
	require.NoFileExists(t, path)
	_, registered := q.registry.Get(job.ID())
	require.False(t, registered)
}

func TestAuditedQueuePreservesRecoveryOnShutdownAndCompletesAfterRestart(t *testing.T) {
	ctx, db, fixture, model := auditTaskFixture(t)
	path := filepath.Join(t.TempDir(), "archive.zip")
	require.NoError(t, os.WriteFile(path, []byte("completed archive"), 0600))
	model.Task.PrivateState = path
	q, job := recoveringQueue(t, ctx, fixture.taskClient, model.Model(), path)
	var failing atomic.Bool
	failing.Store(true)
	attempted := make(chan struct{}, 1)
	db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, mutation entgo.Mutation) (entgo.Value, error) {
			if failing.Load() {
				select {
				case attempted <- struct{}{}:
				default:
				}
				return nil, errors.New("ongoing completion audit outage")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	done := make(chan struct{})
	q.metric.IncBusyWorker()
	q.routineGroup.Run(func() { q.work(job); close(done) })
	select {
	case <-attempted:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reach completion persistence")
	}
	q.Shutdown()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("completion retry did not stop on shutdown")
	}
	require.FileExists(t, path)
	require.Zero(t, job.cleanups.Load())
	require.Zero(t, q.SuccessTasks())
	require.Zero(t, db.AuditLog.Query().CountX(ctx))
	pending := db.Task.GetX(ctx, job.ID())
	require.Equal(t, task.StatusProcessing, pending.Status)
	require.Equal(t, path, pending.PrivateState)
	_, registered := q.registry.Get(job.ID())
	require.True(t, registered)
	failing.Store(false)
	restarted, resumed := recoveringQueue(t, ctx, fixture.taskClient, pending, pending.PrivateState)
	restarted.metric.IncBusyWorker()
	restarted.work(resumed)
	require.Equal(t, task.StatusCompleted, db.Task.GetX(ctx, job.ID()).Status)
	require.Equal(t, 1, db.AuditLog.Query().CountX(ctx))
	require.EqualValues(t, 1, resumed.cleanups.Load())
	require.NoFileExists(t, path)
}

func TestAuditedQueueDoesNotExecuteACompletedTaskFromAStaleWorker(t *testing.T) {
	ctx, db, fixture, winner := auditTaskFixture(t)
	path := filepath.Join(t.TempDir(), "archive.zip")
	require.NoError(t, os.WriteFile(path, []byte("winner owns this recovery file"), 0600))
	stale := *winner.Model()
	q, job := recoveringQueue(t, ctx, fixture.taskClient, &stale, path)
	require.NoError(t, saveTaskToInventory(ctx, winner, task.StatusCompleted, fixture))
	q.metric.IncBusyWorker()
	q.work(job)
	require.Zero(t, job.executions.Load())
	require.Zero(t, job.cleanups.Load())
	require.FileExists(t, path)
	require.Equal(t, task.StatusCompleted, db.Task.GetX(ctx, job.ID()).Status)
	require.Equal(t, 1, db.AuditLog.Query().CountX(ctx))
}
