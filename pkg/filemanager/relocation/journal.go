package relocation

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// Location excludes credentials so rotation preserves durable plans.
func Location(policy *ent.StoragePolicy) string {
	return inventory.StorageLocationFingerprint(policy)
}

// RecordNoop records the first supported plan without generating a target
// object. Unique task/entity identity makes replay independent of Task state.
func RecordNoop(ctx context.Context, db *ent.Client, taskID int, plan *Plan) error {
	e := plan.Entity
	return db.RelocationItem.Create().SetTaskID(taskID).SetOwnerID(plan.Owner.ID).
		SetSourceEntityID(e.ID).SetSourcePolicyID(e.StoragePolicyEntities).SetSourceKey(e.Source).
		SetSourceLocation(Location(plan.Destination)).SetDestinationPolicyID(plan.Destination.ID).
		SetDestinationLocation(Location(plan.Destination)).
		SetSnapshot(&types.RelocationSnapshot{Type: e.Type, Size: e.Size, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, CreatedBy: e.CreatedBy, Props: e.Props}).
		SetReferences(plan.References).SetState(relocationitem.StateNoop).SetTargetEntityID(e.ID).
		SetSourceReadFinished(true).SetSourceCleanup(relocationitem.SourceCleanupUnneeded).
		OnConflictColumns(relocationitem.FieldTaskID, relocationitem.FieldSourceEntityID).DoNothing().Exec(ctx)
}
