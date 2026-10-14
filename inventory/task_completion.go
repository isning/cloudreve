package inventory

import (
	"context"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/task"
)

// Atomic terminal-state protection for journal-backed tasks advanced by a
// replacement worker. Completed metadata belongs to the winner; ordinary
// native tasks retain their existing update behavior.
func (c *taskClient) updatePreservingCompleted(ctx context.Context, model *ent.Task, args *TaskArgs) (*ent.Task, error) {
	stm := c.client.Task.Update().Where(task.ID(model.ID), task.StatusNEQ(task.StatusCompleted)).SetPublicState(args.PublicState)
	if args.PrivateState != "" {
		stm.SetPrivateState(args.PrivateState)
	}
	if args.Status != "" {
		stm.SetStatus(args.Status)
	}
	if _, err := stm.Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to update durable task: %w", err)
	}
	current, err := c.client.Task.Get(ctx, model.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload durable task: %w", err)
	}
	current.Edges = model.Edges
	return current, nil
}
