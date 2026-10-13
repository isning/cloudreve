package workflows

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/queue"
	"github.com/gofrs/uuid"
)

type RelocateTask struct{ *queue.DBTask }
type RelocateCommand struct {
	Sources         []string `json:"sources"`
	DestinationID   int      `json:"destination_id"`
	DestinationName string   `json:"destination_name"`
	NodeID          int      `json:"node_id"`
	Phase           string   `json:"phase"`
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
	if _, err := relocation.PlanNoop(ctx, dep, owner.ID, command.Sources, command.DestinationID); err != nil {
		return task.StatusError, fmt.Errorf("migration planning failed: %s: %w", err.Error(), queue.CriticalErr)
	}
	state := NodeState{NodeID: command.NodeID}
	node, err := allocateNode(ctx, dep, &state, types.NodeCapabilityRelocate)
	if err != nil || !node.IsMaster() {
		return task.StatusError, fmt.Errorf("no supported migration execution node: %w", queue.CriticalErr)
	}
	command.NodeID = state.NodeID
	command.Phase = "completed"
	encoded, err := json.Marshal(command)
	if err != nil {
		return task.StatusError, err
	}
	t.Lock()
	t.Task.PrivateState = string(encoded)
	t.Unlock()
	return task.StatusCompleted, nil
}
func (t *RelocateTask) Summarize(encoder hashid.Encoder) *queue.Summary {
	var command RelocateCommand
	if err := json.Unmarshal([]byte(t.State()), &command); err != nil {
		return nil
	}
	return &queue.Summary{NodeID: command.NodeID, Phase: command.Phase, Props: map[string]any{"src_multiple": command.Sources, "dst_policy_id": hashid.EncodePolicyID(encoder, command.DestinationID), "dst_policy_name": command.DestinationName}}
}
