package inventory

import (
	"context"
	"errors"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

var (
	ErrStoragePolicyInUse   = errors.New("storage policy has active upload or migration dependencies")
	ErrStoragePolicyGranted = errors.New("storage policy is granted to an active group")
)

// LockStoragePolicy must run inside the caller's transaction. Uploads acquire
// the owner quota lock first; administrators acquire only this policy lock.
// A real no-op write supplies a lifecycle lock on every supported dialect.
func LockStoragePolicy(ctx context.Context, c *ent.Client, id int) (*ent.StoragePolicy, error) {
	err := c.StoragePolicy.Update().Where(storagepolicy.ID(id), storagepolicy.DeletedAtIsNil()).AddMaxSize(0).Exec(ctx)
	if err != nil {
		return nil, err
	}
	return c.StoragePolicy.Query().Where(storagepolicy.ID(id), storagepolicy.DeletedAtIsNil()).WithNode().Only(ctx)
}

func SameStorageLocation(a, b *ent.StoragePolicy) bool {
	if a.Type != b.Type || a.Server != b.Server || a.BucketName != b.BucketName || a.NodeID != b.NodeID {
		return false
	}
	as, bs := a.Settings, b.Settings
	if as == nil {
		as = &types.PolicySetting{}
	}
	if bs == nil {
		bs = &types.PolicySetting{}
	}
	return as.ServerSideEndpoint == bs.ServerSideEndpoint && as.OdDriver == bs.OdDriver && as.Region == bs.Region && as.S3ForcePathStyle == bs.S3ForcePathStyle
}

func checkUploadPolicyDependencies(ctx context.Context, c *ent.Client, id int) error {
	pending, err := c.Entity.Query().Where(entity.StoragePolicyEntities(id), entity.UploadSessionIDNotNil()).All(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	for _, item := range pending {
		// Legacy placeholders without a recorded expiry require native cleanup.
		if item.Props == nil || item.Props.UploadExpiresAt == 0 || item.Props.UploadExpiresAt > now {
			return ErrStoragePolicyInUse
		}
	}
	return checkRelocationPolicyDependencies(ctx, c, id)
}

// Durable records remain authoritative after terminal status, history cleanup
// or account deletion. Unknown external writes are dependencies even if an
// earlier compensation pass observed no object at their exact owned key.
func checkRelocationPolicyDependencies(ctx context.Context, c *ent.Client, id int) error {
	used, err := c.RelocationItem.Query().Where(
		relocationitem.Or(relocationitem.SourcePolicyID(id), relocationitem.DestinationPolicyID(id)),
		relocationitem.Or(
			relocationitem.StateNotIn(relocationitem.StateCommitted, relocationitem.StateNoop, relocationitem.StateFailed),
			relocationitem.SourceCleanupEQ(relocationitem.SourceCleanupPending),
			relocationitem.HasAttemptsWith(relocationattempt.Or(
				relocationattempt.CleanupEQ(relocationattempt.CleanupPending),
				relocationattempt.IoStateIn(relocationattempt.IoStateInFlight, relocationattempt.IoStateUnknown),
			)),
		),
	).Exist(ctx)
	if err != nil {
		return err
	}
	if used {
		return ErrStoragePolicyInUse
	}
	return nil
}

func checkGroupPolicyDependencies(ctx context.Context, c *ent.Client, id int) error {
	granted, err := c.GroupPolicy.Query().Where(grouppolicy.StoragePolicyID(id), grouppolicy.HasGroupWith(group.DeletedAtIsNil())).Exist(ctx)
	if err != nil {
		return err
	}
	if granted {
		return ErrStoragePolicyGranted
	}
	return nil
}
