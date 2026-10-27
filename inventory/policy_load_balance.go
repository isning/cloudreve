package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/policyloadbalance"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

var ErrInvalidLoadBalancePolicy = errors.New("invalid load balance storage policy")
var ErrStoragePolicyInPool = errors.New("storage policy belongs to a load balance pool")

const storagePolicyWriteLock = "storage_extension_policy_write_lock"

// Policy configuration writes share one native row lock before any policy rows.
// Inherited InnoDB transactions retain gap locks even for empty memberships.
func (c *storagePolicyClient) lockConfiguration(ctx context.Context) error {
	return c.client.Setting.Create().SetName(storagePolicyWriteLock).SetValue("").
		OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx)
}

// validatePool locks the parent and children by ID, matching group grants and
// relocation, before checking membership, deletion and type changes.
func (c *storagePolicyClient) validatePool(ctx context.Context, policy *ent.StoragePolicy) error {
	if policy.Type != types.PolicyTypeLoadBalance {
		if len(policy.Edges.PolicyLoadBalance) > 0 {
			return fmt.Errorf("%w: only load balance policies can have children", ErrInvalidLoadBalancePolicy)
		}
		return nil
	}
	seen := make(map[int]bool)
	ids := make([]int, 0, len(policy.Edges.PolicyLoadBalance))
	if policy.ID > 0 {
		ids = append(ids, policy.ID)
	}
	var total int64
	for _, child := range policy.Edges.PolicyLoadBalance {
		if child == nil || child.StoragePolicyID <= 0 || child.StoragePolicyID == policy.ID || seen[child.StoragePolicyID] || child.Weight < 0 || child.Weight > 9007199254740991 {
			return ErrInvalidLoadBalancePolicy
		}
		total += int64(child.Weight)
		if total > 9007199254740991 {
			return fmt.Errorf("%w: total weight exceeds the supported integer range", ErrInvalidLoadBalancePolicy)
		}
		seen[child.StoragePolicyID] = true
		ids = append(ids, child.StoragePolicyID)
	}
	sort.Ints(ids)
	for _, id := range ids {
		child, err := LockStoragePolicy(ctx, c.client, id)
		if ent.IsNotFound(err) && id != policy.ID {
			return fmt.Errorf("%w: child policy does not exist", ErrInvalidLoadBalancePolicy)
		}
		if err != nil {
			return err
		}
		if id != policy.ID && child.Type == types.PolicyTypeLoadBalance {
			return fmt.Errorf("%w: nested load balance policies are not supported", ErrInvalidLoadBalancePolicy)
		}
	}
	if policy.ID > 0 {
		if err := c.checkPoolMembership(ctx, policy.ID); err != nil {
			return err
		}
		// Earlier policy locks may have established a MySQL snapshot before
		// the parent lock. Read dependencies committed before that lock now.
		used, err := c.client.Entity.Query().Where(entity.StoragePolicyEntities(policy.ID), storageLifecycleRead).Exist(ctx)
		if err != nil {
			return err
		}
		if used {
			return fmt.Errorf("%w: a policy with existing entities cannot become a pool", ErrInvalidLoadBalancePolicy)
		}
	}
	return nil
}

func (c *storagePolicyClient) checkPoolMembership(ctx context.Context, id int) error {
	used, err := c.client.PolicyLoadBalance.Query().Where(policyloadbalance.StoragePolicyID(id), storageLifecycleRead).Exist(ctx)
	if err != nil {
		return err
	}
	if used {
		return ErrStoragePolicyInPool
	}
	return nil
}

func (c *storagePolicyClient) savePool(ctx context.Context, input, saved *ent.StoragePolicy) error {
	// Omission preserves assignments for older administration clients.
	if input.Type == types.PolicyTypeLoadBalance && input.Edges.PolicyLoadBalance == nil {
		return nil
	}
	// New policies have no old memberships. An empty-range delete can retain
	// gap locks that deadlock independent inserts in inherited transactions.
	if input.ID > 0 {
		if _, err := c.client.PolicyLoadBalance.Delete().Where(policyloadbalance.LoadBalanceID(saved.ID)).Exec(ctx); err != nil {
			return err
		}
	}
	for _, child := range input.Edges.PolicyLoadBalance {
		if err := c.client.PolicyLoadBalance.Create().SetLoadBalanceID(saved.ID).
			SetStoragePolicyID(child.StoragePolicyID).SetWeight(child.Weight).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
