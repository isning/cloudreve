package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/gofrs/uuid"
)

type RelocateTask struct{ *queue.DBTask }

func (*RelocateTask) PreserveCompleted() bool { return true }

func (*RelocateTask) CancellationDrainTimeout() time.Duration { return 5 * time.Second }

type RelocateCommand struct {
	Sources         []string             `json:"sources"`
	DestinationID   int                  `json:"destination_id"`
	DestinationName string               `json:"destination_name"`
	NodeID          int                  `json:"node_id"`
	Phase           string               `json:"phase"`
	Progress        *relocation.Progress `json:"progress,omitempty"`
}

func init() { queue.RegisterResumableTaskFactory(queue.RelocateTaskType, NewRelocateTaskFromModel) }
func NewRelocateTaskFromModel(model *ent.Task) queue.Task {
	return &RelocateTask{DBTask: &queue.DBTask{Task: model}}
}
func NewRelocateTask(ctx context.Context, sources []string, destination *ent.StoragePolicy, nodeID int) (queue.Task, error) {
	command := RelocateCommand{Sources: sources, DestinationID: destination.ID, DestinationName: destination.Name, NodeID: nodeID, Phase: "planning"}
	encoded, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	correlationID := logging.CorrelationID(ctx)
	if correlationID == uuid.Nil {
		correlationID = uuid.Must(uuid.NewV4())
	}
	return &RelocateTask{DBTask: &queue.DBTask{DirectOwner: inventory.UserFromContext(ctx), Task: &ent.Task{Type: queue.RelocateTaskType, PrivateState: string(encoded), PublicState: &types.TaskPublicState{}, CorrelationID: correlationID}}}, nil
}
func (t *RelocateTask) Do(ctx context.Context) (task.Status, error) {
	var command RelocateCommand
	if err := json.Unmarshal([]byte(t.State()), &command); err != nil {
		return task.StatusError, fmt.Errorf("invalid migration command: %w", queue.CriticalErr)
	}
	owner := inventory.UserFromContext(ctx)
	if owner == nil {
		return task.StatusError, fmt.Errorf("migration owner is unavailable: %w", queue.CriticalErr)
	}
	dep := dependency.FromContext(ctx)
	state := NodeState{NodeID: command.NodeID}
	node, err := allocateNode(ctx, dep, &state, types.NodeCapabilityRelocate)
	if err != nil || !node.IsMaster() {
		return task.StatusError, fmt.Errorf("no supported migration execution node: %w", queue.CriticalErr)
	}
	command.NodeID = state.NodeID
	// Repair missing maintenance before crossing another external boundary.
	if err := manager.EnsureRelocationCleanup(ctx, dep, t.ID()); err != nil {
		return task.StatusError, errors.New("failed to schedule migration compensation")
	}
	done, err := relocation.AdvanceSingle(ctx, dep, t.ID(), owner.ID, command.Sources, command.DestinationID)
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	cleanupErr := manager.EnsureRelocationCleanup(cleanupCtx, dep, t.ID())
	cleanupCancel()
	if cleanupErr != nil {
		dep.Logger().Warning("Migration compensation scheduling deferred; journal retained")
	}
	if errors.Is(err, relocation.ErrLeaseBusy) || errors.Is(err, relocation.ErrLeaseLost) {
		progress, reportErr := relocation.ReadProgress(ctx, dep.DBClient(), t.ID(), false)
		if reportErr == nil && progress.Phase == "completed" {
			done, err = true, nil
		} else {
			t.ResumeAfter(30 * time.Second)
			return task.StatusSuspending, nil
		}
	}

	if err != nil {
		command.Phase = "failed"
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		command.Progress, _ = relocation.ReadProgress(reportCtx, dep.DBClient(), t.ID(), true)
		cancel()
		t.saveCommand(command)
		return task.StatusError, fmt.Errorf("%s: %w", err.Error(), queue.CriticalErr)
	}
	command.Phase = "transferring"
	if done {
		command.Phase = "completed"
	}
	command.Progress, err = relocation.ReadProgress(ctx, dep.DBClient(), t.ID(), false)
	if err != nil {
		return task.StatusError, err
	}
	if err := t.saveCommand(command); err != nil {
		return task.StatusError, err
	}
	if done {
		return task.StatusCompleted, nil
	}
	t.ResumeAfter(0)
	return task.StatusSuspending, nil
}
func (t *RelocateTask) Summarize(encoder hashid.Encoder) *queue.Summary {
	var command RelocateCommand
	if err := json.Unmarshal([]byte(t.State()), &command); err != nil {
		return nil
	}
	props := map[string]any{"src_multiple": command.Sources, "dst_policy_id": hashid.EncodePolicyID(encoder, command.DestinationID), "dst_policy_name": command.DestinationName}
	if p := command.Progress; p != nil {
		command.Phase = p.Phase
		props["entities_total"], props["entities_completed"], props["entities_failed"] = p.Total, p.Completed, p.Failed
		props["bytes_total"], props["bytes_copied"] = p.Bytes, p.Copied
	}
	return &queue.Summary{NodeID: command.NodeID, Phase: command.Phase, Props: props}
}

func (t *RelocateTask) saveCommand(command RelocateCommand) error {
	encoded, err := json.Marshal(command)
	if err != nil {
		return err
	}
	t.Lock()
	t.Task.PrivateState = string(encoded)
	t.Unlock()
	return nil
}

// RefreshSummary reconstructs facts even if Task state persistence was interrupted.
func (t *RelocateTask) RefreshSummary(ctx context.Context) error {
	var command RelocateCommand
	if err := json.Unmarshal([]byte(t.State()), &command); err != nil {
		return errors.New("invalid migration summary")
	}
	t.Lock()
	failed := t.Task.Status == task.StatusError
	t.Unlock()
	progress, err := relocation.ReadProgress(ctx, dependency.FromContext(ctx).DBClient(), t.ID(), failed)
	if err != nil {
		return err
	}
	command.Progress = progress
	command.Phase = progress.Phase
	return t.saveCommand(command)
}

func (t *RelocateTask) DurableProgress(ctx context.Context) (queue.Progresses, error) {
	t.Lock()
	failed := t.Task.Status == task.StatusError
	t.Unlock()
	p, err := relocation.ReadProgress(ctx, dependency.FromContext(ctx).DBClient(), t.ID(), failed)
	if err != nil {
		return nil, err
	}
	return queue.Progresses{
		"relocate_count":  {Total: p.Total, Current: p.Completed},
		"relocate_size":   {Total: p.Bytes, Current: p.Copied},
		"relocate_failed": {Total: p.Total, Current: p.Failed},
	}, nil
}

func (t *RelocateTask) Progress(ctx context.Context) queue.Progresses {
	p, _ := t.DurableProgress(ctx)
	return p
}
