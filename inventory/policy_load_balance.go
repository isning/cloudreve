package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/policyloadbalance"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

var ErrInvalidLoadBalancePolicy = errors.New("invalid load balance storage policy")
var ErrStoragePolicyInPool = errors.New("storage policy belongs to a load balance pool")

// validatePool locks children against concurrent deletion and type changes.
func (c *storagePolicyClient) validatePool(ctx context.Context, policy *ent.StoragePolicy) error {
	if policy.Type != types.PolicyTypeLoadBalance {
		if len(policy.Edges.PolicyLoadBalance) > 0 {
			return fmt.Errorf("%w: only load balance policies can have children", ErrInvalidLoadBalancePolicy)
		}
		return nil
	}
	if policy.ID > 0 {
		if err := c.checkPoolMembership(ctx, policy.ID); err != nil {
			return err
		}
		used, err := c.client.Entity.Query().Where(entity.StoragePolicyEntities(policy.ID)).Exist(ctx)
		if err != nil {
			return err
		}
		if used {
			return fmt.Errorf("%w: a policy with existing entities cannot become a pool", ErrInvalidLoadBalancePolicy)
		}
	}
	seen := make(map[int]bool)
	ids := make([]int, 0, len(policy.Edges.PolicyLoadBalance))
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
		if ent.IsNotFound(err) {
			return fmt.Errorf("%w: child policy does not exist", ErrInvalidLoadBalancePolicy)
		}
		if err != nil {
			return err
		}
		if child.Type == types.PolicyTypeLoadBalance {
			return fmt.Errorf("%w: nested load balance policies are not supported", ErrInvalidLoadBalancePolicy)
		}
	}
	return nil
}

func (c *storagePolicyClient) checkPoolMembership(ctx context.Context, id int) error {
	used, err := c.client.PolicyLoadBalance.Query().Where(policyloadbalance.StoragePolicyID(id)).Exist(ctx)
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
	if _, err := c.client.PolicyLoadBalance.Delete().Where(policyloadbalance.LoadBalanceID(saved.ID)).Exec(ctx); err != nil {
		return err
	}
	for _, child := range input.Edges.PolicyLoadBalance {
		if err := c.client.PolicyLoadBalance.Create().SetLoadBalanceID(saved.ID).
			SetStoragePolicyID(child.StoragePolicyID).SetWeight(child.Weight).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
