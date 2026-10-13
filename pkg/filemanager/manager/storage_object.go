package manager

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
)

// Native recycler, imports and migration streams share the durable gate.
// The transaction stays open over Delete: a second process cannot admit a
// successful alias after the dependency check but before provider deletion.
func (m *manager) recycleEntityLocation(ctx context.Context, candidate fs.Entity) error {
	fc, tx, ctx, err := inventory.WithTx(ctx, m.dep.FileClient())
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	db := fc.GetClient()
	policy, err := inventory.LockStoragePolicy(ctx, db, candidate.PolicyID())
	if err != nil {
		return err
	}
	location, err := inventory.LockStorageObject(ctx, db, policy, candidate.Source())
	if err != nil {
		return err
	}
	current, err := db.Entity.Get(ctx, candidate.ID())
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Source != candidate.Source() || current.StoragePolicyEntities != candidate.PolicyID() {
		return nil
	}
	// Explicit native recycle IDs are also rechecked, never a stale force bypass.
	referenced, err := inventory.StorageObjectReferenced(ctx, db, policy, current.Source)
	if err != nil {
		return err
	}
	if referenced {
		return nil
	}
	plans, err := db.RelocationItem.Query().Where(relocationitem.SourceKey(current.Source), relocationitem.StateIn(relocationitem.StatePlanned, relocationitem.StateCopying, relocationitem.StateVerified)).All(ctx)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		sourcePolicy, err := db.StoragePolicy.Get(ctx, plan.SourcePolicyID)
		if err != nil {
			return err
		}
		if inventory.StorageObjectKey(sourcePolicy, plan.SourceKey) == location.Key {
			return nil
		}
	}
	d, err := m.GetStorageDriver(ctx, policy)
	if err != nil {
		return err
	}
	if current.Props == nil || !current.Props.UnlinkOnly {
		failed, err := d.Delete(ctx, current.Source)
		if err != nil || len(failed) > 0 {
			return errors.New("physical storage cleanup failed")
		}
		if err := db.StorageObject.UpdateOne(location).SetRetired(true).Exec(ctx); err != nil {
			return err
		}
	}
	if current.UploadSessionID != nil {
		if value, ok := m.kv.Get(UploadSessionCachePrefix + current.UploadSessionID.String()); ok {
			session := value.(fs.UploadSession)
			if err := d.CancelToken(ctx, &session); err != nil {
				m.l.Warning("Failed to cancel retired upload token")
			}
			_ = m.kv.Delete(UploadSessionCachePrefix, current.UploadSessionID.String())
		}
	}
	reduced, err := fc.RemoveEntitiesByID(ctx, current.ID)
	if err != nil {
		return fmt.Errorf("remove retired entity: %w", err)
	}
	tx.AppendStorageDiff(reduced)
	return inventory.CommitWithStorageDiff(ctx, tx, m.l, m.dep.UserClient())
}
