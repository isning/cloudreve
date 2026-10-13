package relocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// Location fingerprints only physical addressing properties, so credential
// rotation does not invalidate durable plans or expose secrets in the journal.
func Location(policy *ent.StoragePolicy) string {
	settings := policy.Settings
	if settings == nil {
		settings = &types.PolicySetting{}
	}
	b, _ := json.Marshal([]any{policy.Type, policy.Server, policy.BucketName, policy.NodeID, settings.ServerSideEndpoint, settings.OdDriver, settings.Region, settings.S3ForcePathStyle})
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
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
