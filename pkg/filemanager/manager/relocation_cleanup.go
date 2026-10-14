package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationplan"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/gofrs/uuid"
)

type relocationCleanupCommand struct {
	TaskID int `json:"task_id"`
}
type RelocationCleanupTask struct{ *queue.DBTask }

func init() {
	queue.RegisterResumableTaskFactory(queue.RelocationCleanupTaskType, NewRelocationCleanupTaskFromModel)
}
func NewRelocationCleanupTaskFromModel(model *ent.Task) queue.Task {
	return &RelocationCleanupTask{DBTask: &queue.DBTask{Task: model}}
}

// A system-owned native task is published atomically with its plan association.
// Account/history deletion cannot discard the independent journal obligation.
func EnsureRelocationCleanup(ctx context.Context, dep dependency.Dep, taskID int) error {
	db := dep.DBClient()
	header, err := db.RelocationPlan.Query().Where(relocationplan.TaskID(taskID)).Only(ctx)
	if ent.IsNotFound(err) {
		// Early journal versions had no plan header. Preserve and adopt their
		// complete single-file facts before independent maintenance is scheduled.
		items, loadErr := db.RelocationItem.Query().Where(relocationitem.TaskID(taskID)).All(ctx)
		if loadErr != nil {
			return loadErr
		}
		if len(items) == 0 {
			return nil
		}
		owner, destination := items[0].OwnerID, items[0].DestinationPolicyID
		ids := map[int]bool{}
		for _, item := range items {
			if item.OwnerID != owner || item.DestinationPolicyID != destination {
				return errors.New("inconsistent legacy compensation journal")
			}
			for _, reference := range item.References {
				ids[reference.FileID] = true
			}
		}
		files := make([]int, 0, len(ids))
		for id := range ids {
			files = append(files, id)
		}
		sort.Ints(files)
		if err := db.RelocationPlan.Create().SetTaskID(taskID).SetOwnerID(owner).SetDestinationPolicyID(destination).SetFileIds(files).OnConflictColumns(relocationplan.FieldTaskID).DoNothing().Exec(ctx); err != nil {
			return err
		}
		header, err = db.RelocationPlan.Query().Where(relocationplan.TaskID(taskID)).Only(ctx)
	}
	if err != nil {
		return err
	}
	pending, err := relocationCleanupPending(ctx, db, taskID)
	if err != nil || !pending {
		return err
	}
	anonymous, err := dep.UserClient().AnonymousUser(ctx)
	if err != nil {
		return err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.RelocationPlan.UpdateOneID(header.ID).AddCleanupTaskID(0).Exec(ctx); err != nil {
		return err
	}
	header, err = tx.RelocationPlan.Get(ctx, header.ID)
	if err != nil {
		return err
	}
	if header.CleanupTaskID > 0 {
		existing, err := tx.Task.Get(ctx, header.CleanupTaskID)
		if err == nil && existing.Type == queue.RelocationCleanupTaskType && existing.Status != task.StatusCompleted && existing.Status != task.StatusError && existing.Status != task.StatusCanceled {
			return nil
		}
		if err != nil && !ent.IsNotFound(err) {
			return err
		}
	}
	command, _ := json.Marshal(relocationCleanupCommand{TaskID: taskID})
	model, err := tx.Task.Create().SetType(queue.RelocationCleanupTaskType).SetStatus(task.StatusQueued).SetPrivateState(string(command)).SetPublicState(&types.TaskPublicState{}).SetCorrelationID(logging.CorrelationID(ctx)).Save(ctx)
	if err != nil {
		return err
	}
	if err := tx.RelocationPlan.UpdateOne(header).SetCleanupTaskID(model.ID).Exec(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	model.SetUser(anonymous)
	return dep.EntityRecycleQueue(ctx).QueueTask(ctx, NewRelocationCleanupTaskFromModel(model))
}

func relocationCleanupPending(ctx context.Context, db *ent.Client, taskID int) (bool, error) {
	return db.RelocationItem.Query().Where(relocationitem.TaskID(taskID), relocationitem.Or(relocationitem.SourceCleanupEQ(relocationitem.SourceCleanupPending), relocationitem.HasAttemptsWith(relocationattempt.CleanupEQ(relocationattempt.CleanupPending)))).Exist(ctx)
}

// Cron also repairs a process crash between publishing a plan and scheduling.
func ensureAllRelocationCleanup(ctx context.Context, dep dependency.Dep) error {
	ids, err := dep.DBClient().RelocationItem.Query().Unique(true).Select(relocationitem.FieldTaskID).Ints(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := EnsureRelocationCleanup(ctx, dep, id); err != nil {
			return err
		}
	}
	return nil
}

func (t *RelocationCleanupTask) Do(ctx context.Context) (task.Status, error) {
	var command relocationCleanupCommand
	if json.Unmarshal([]byte(t.State()), &command) != nil || command.TaskID <= 0 {
		return task.StatusError, fmt.Errorf("invalid compensation command: %w", queue.CriticalErr)
	}
	dep := dependency.FromContext(ctx)
	m := NewFileManager(dep, inventory.UserFromContext(ctx)).(*manager)
	defer m.Recycle()
	if err := m.collectRelocation(ctx, command.TaskID); err != nil {
		t.OnRetry(errors.New("migration compensation deferred"))
		dep.Logger().Warning("Migration compensation deferred; journal retained")
		t.ResumeAfter(10 * time.Second)
		return task.StatusSuspending, nil
	}
	pending, err := relocationCleanupPending(ctx, dep.DBClient(), command.TaskID)
	if err != nil || pending {
		t.ResumeAfter(10 * time.Second)
		return task.StatusSuspending, nil
	}
	return task.StatusCompleted, nil
}

func (m *manager) collectRelocation(ctx context.Context, taskID int) error {
	items, err := m.dep.DBClient().RelocationItem.Query().Where(relocationitem.TaskID(taskID)).WithAttempts().All(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, item := range items {
		item, err = m.abandonMissingRelocation(ctx, item)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		for _, attempt := range item.Edges.Attempts {
			if attempt.Cleanup != relocationattempt.CleanupPending {
				continue
			}
			if err := m.collectRelocationTarget(ctx, item, attempt); err != nil && first == nil {
				first = err
			}
		}
		if item.SourceCleanup == relocationitem.SourceCleanupPending {
			if err := m.collectRelocationSource(ctx, item); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// Missing owners/history cannot resume a commit. Revoke the old fence while
// preserving every independent reader and remote I/O fact for compensation.
func (m *manager) abandonMissingRelocation(ctx context.Context, item *ent.RelocationItem) (*ent.RelocationItem, error) {
	if item.State == relocationitem.StateCommitted || item.State == relocationitem.StateNoop || item.State == relocationitem.StateFailed {
		return item, nil
	}
	db := m.dep.DBClient()
	ownerExists, err := db.User.Query().Where(user.ID(item.OwnerID), user.StatusEQ(user.StatusActive)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	mainExists, err := db.Task.Query().Where(task.ID(item.TaskID), task.Type(queue.RelocateTaskType), task.UserTasks(item.OwnerID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if ownerExists && mainExists {
		return item, nil
	}
	_, err = db.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.StateNotIn(relocationitem.StateCommitted, relocationitem.StateNoop, relocationitem.StateFailed)).AddFence(1).SetState(relocationitem.StateFailed).SetError("migration owner or task is unavailable").SetLeaseOwner("").ClearLeaseUntil().Save(ctx)
	if err != nil {
		return nil, err
	}
	return db.RelocationItem.Query().Where(relocationitem.ID(item.ID)).WithAttempts().Only(ctx)
}

func ownedRelocationKey(item *ent.RelocationItem, attempt *ent.RelocationAttempt) bool {
	parts := strings.Split(path.Clean(attempt.TargetKey), "/")
	if len(parts) < 4 || parts[len(parts)-4] != ".cloudreve-relocation" || parts[len(parts)-3] != strconv.Itoa(item.ID) || parts[len(parts)-2] != strconv.FormatInt(attempt.Fence, 10) || attempt.ItemID != item.ID {
		return false
	}
	_, err := uuid.FromString(parts[len(parts)-1])
	return err == nil
}

func (m *manager) collectRelocationTarget(ctx context.Context, item *ent.RelocationItem, attempt *ent.RelocationAttempt) error {
	if !ownedRelocationKey(item, attempt) {
		return errors.New("unrecognized compensation ownership")
	}
	fc, tx, ctx, err := inventory.WithTx(ctx, m.dep.FileClient())
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	c := fc.GetClient()
	policy, err := inventory.LockStoragePolicy(ctx, c, item.DestinationPolicyID)
	if err != nil {
		return err
	}
	if inventory.StorageLocationFingerprint(policy) != item.DestinationLocation {
		return errors.New("compensation destination changed")
	}
	location, err := inventory.LockStorageObject(ctx, c, policy, attempt.TargetKey)
	if err != nil {
		return err
	}
	current, err := c.RelocationItem.Get(ctx, item.ID)
	if err != nil {
		return err
	}
	attempt, err = c.RelocationAttempt.Get(ctx, attempt.ID)
	if err != nil {
		return err
	}
	if attempt.Cleanup != relocationattempt.CleanupPending {
		return nil
	}
	if current.State == relocationitem.StateCommitted && current.ActiveAttemptID == attempt.ID {
		if err := c.RelocationAttempt.UpdateOne(attempt).SetCleanup(relocationattempt.CleanupRetained).Exec(ctx); err != nil {
			return err
		}
		return inventory.Commit(tx)
	}
	// Active verified targets may be reused after a takeover, including an
	// older attempt fence. Active writes/verification never become deletion work.
	terminal := current.State == relocationitem.StateFailed || current.State == relocationitem.StateCommitted || current.State == relocationitem.StateNoop
	if !terminal && current.ActiveAttemptID == attempt.ID {
		return nil
	}
	if !terminal && attempt.Fence >= current.Fence {
		return nil
	}
	referenced, err := inventory.StorageObjectReferenced(ctx, c, policy, attempt.TargetKey)
	if err != nil || referenced {
		return err
	}
	d, err := m.GetStorageDriver(ctx, policy)
	if err != nil {
		return err
	}
	failed, err := d.Delete(ctx, attempt.TargetKey)
	if err != nil || len(failed) > 0 {
		return errors.New("compensation deletion failed")
	}
	if err := c.StorageObject.UpdateOne(location).SetRetired(true).Exec(ctx); err != nil {
		return err
	}
	// Absence or one successful Delete is not proof against a late remote PUT.
	if attempt.IoState == relocationattempt.IoStateEnded || attempt.IoState == relocationattempt.IoStateNotStarted {
		if err := c.RelocationAttempt.UpdateOne(attempt).SetCleanup(relocationattempt.CleanupCleaned).Exec(ctx); err != nil {
			return err
		}
	}
	return inventory.Commit(tx)
}

func (m *manager) collectRelocationSource(ctx context.Context, item *ent.RelocationItem) error {
	if item.State != relocationitem.StateCommitted && item.State != relocationitem.StateFailed && item.State != relocationitem.StateNoop {
		return nil
	}
	fc, tx, ctx, err := inventory.WithTx(ctx, m.dep.FileClient())
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	c := fc.GetClient()
	policy, err := inventory.LockStoragePolicy(ctx, c, item.SourcePolicyID)
	if err != nil {
		return err
	}
	if inventory.StorageLocationFingerprint(policy) != item.SourceLocation {
		return errors.New("compensation source changed")
	}
	location, err := inventory.LockStorageObject(ctx, c, policy, item.SourceKey)
	if err != nil {
		return err
	}
	current, err := c.RelocationItem.Get(ctx, item.ID)
	if err != nil {
		return err
	}
	if current.SourceCleanup != relocationitem.SourceCleanupPending {
		return nil
	}
	if current.State != relocationitem.StateCommitted && current.State != relocationitem.StateFailed && current.State != relocationitem.StateNoop {
		return nil
	}
	// Ordinary retained associations remain under the native recycler's lifetime.
	live, err := inventory.StorageObjectEntityReferenced(ctx, c, policy, current.SourceKey)
	if err != nil {
		return err
	}
	if live {
		if err := c.RelocationItem.UpdateOne(current).SetSourceCleanup(relocationitem.SourceCleanupRetained).Exec(ctx); err != nil {
			return err
		}
		return inventory.Commit(tx)
	}
	reading, err := inventory.StorageObjectReferenced(ctx, c, policy, current.SourceKey)
	if err != nil || reading {
		return err
	}
	attempts, err := c.RelocationAttempt.Query().Where(relocationattempt.ItemID(item.ID), relocationattempt.SourceReadFinished(false)).All(ctx)
	if err != nil {
		return err
	}
	// Preserve old journals whose read lifetime predates independent reader rows.
	for _, attempt := range attempts {
		if attempt.IoState != relocationattempt.IoStateNotStarted &&
			!(attempt.ID == current.ActiveAttemptID && current.SourceReadFinished && attempt.IoState == relocationattempt.IoStateEnded) {
			return nil
		}
	}
	d, err := m.GetStorageDriver(ctx, policy)
	if err != nil {
		return err
	}
	failed, err := d.Delete(ctx, current.SourceKey)
	if err != nil || len(failed) > 0 {
		return errors.New("old source deletion failed")
	}
	if err := c.StorageObject.UpdateOne(location).SetRetired(true).Exec(ctx); err != nil {
		return err
	}
	if err := c.RelocationItem.UpdateOne(current).SetSourceCleanup(relocationitem.SourceCleanupCleaned).Exec(ctx); err != nil {
		return err
	}
	return inventory.Commit(tx)
}
