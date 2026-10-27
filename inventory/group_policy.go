package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
)

var ErrInvalidGroupPolicies = errors.New("invalid group storage policy assignment")

func (c *groupClient) UpsertWithPolicies(ctx context.Context, input *ent.Group, requested *[]int) (*ent.Group, error) {
	// Independent grant replacements must not retain InnoDB gap locks.
	gc, tx, ctx, err := WithTxOptions(ctx, c, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer Rollback(tx)
	var ids []int
	defaultID := 0
	hadGrants := false
	if input.ID > 0 {
		current, err := gc.lockGroup(ctx, input.ID)
		if err != nil {
			return nil, err
		}
		// Omission preserves binding state, including its current derived
		// default, under the group lock. No snapshot of grants is needed.
		defaultID = current.StoragePolicyID
		// The migration and native grant writes maintain this mirror atomically.
		// Its locked presence avoids deleting an empty grant index range, even
		// in an inherited transaction. It does not authorize destinations.
		hadGrants = current.StoragePolicyID > 0
	}
	writeGrants := requested != nil
	if requested != nil {
		ids = append([]int(nil), (*requested)...)
		if len(ids) == 0 && input.ID != AnonymousGroupID {
			return nil, ErrInvalidGroupPolicies
		}
		defaultID = 0
		if len(ids) > 0 {
			defaultID = ids[0]
		}
	} else if input.ID == 0 {
		return nil, ErrInvalidGroupPolicies
	}
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return nil, ErrInvalidGroupPolicies
		}
		seen[id] = true
	}
	// Lock order must stay stable even while an ordinary policy becomes a pool.
	// Keep the administrator's separate grant order unchanged.
	lockIDs := append([]int(nil), ids...)
	sort.Ints(lockIDs)
	for _, id := range lockIDs {
		_, err := LockStoragePolicy(ctx, gc.client, id)
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("%w: policy does not exist", ErrInvalidGroupPolicies)
		}
		if err != nil {
			return nil, err
		}
	}
	input.Edges.StoragePolicies = nil
	if defaultID > 0 {
		input.Edges.StoragePolicies = &ent.StoragePolicy{ID: defaultID}
	}
	result, err := gc.Upsert(ctx, input)
	if err != nil {
		return nil, err
	}
	if writeGrants {
		if hadGrants {
			if _, err := gc.client.GroupPolicy.Delete().Where(grouppolicy.GroupID(result.ID)).Exec(ctx); err != nil {
				return nil, err
			}
		}
		for position, id := range ids {
			if err := gc.client.GroupPolicy.Create().SetGroupID(result.ID).SetStoragePolicyID(id).SetPosition(position).Exec(ctx); err != nil {
				return nil, err
			}
		}
	}
	if err := Commit(tx); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *groupClient) lockGroup(ctx context.Context, id int) (*ent.Group, error) {
	// A no-op can report snapshot NotFound; the locked current read decides.
	if _, err := c.client.Group.UpdateOneID(id).Where(group.DeletedAtIsNil()).AddSpeedLimit(0).Save(ctx); err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	return c.client.Group.Query().Where(group.ID(id), group.DeletedAtIsNil(), storageLifecycleRead).Only(ctx)
}
