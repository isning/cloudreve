package storagepolicy

import (
	"errors"
	"math/rand/v2"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

var ErrNoAvailableChildren = errors.New("load balance storage policy has no available children with positive weight")

// Choose implements weighted placement, without changing the logical policy.
// Resolved entity locations remain ordinary policies handled by existing drivers.
func Choose(policy *ent.StoragePolicy) (*ent.StoragePolicy, error) {
	if policy == nil {
		return nil, ErrNoAvailablePolicies
	}
	if policy.Type != types.PolicyTypeLoadBalance {
		return policy, nil
	}
	var total int64
	for _, member := range policy.Edges.PolicyLoadBalance {
		if availableChild(member) {
			if member.Weight > 9007199254740991 || total > 9007199254740991-int64(member.Weight) {
				return nil, ErrNoAvailableChildren
			}
			total += int64(member.Weight)
		}
	}
	if total == 0 {
		return nil, ErrNoAvailableChildren
	}
	ticket := rand.Int64N(total)
	for _, member := range policy.Edges.PolicyLoadBalance {
		if availableChild(member) {
			ticket -= int64(member.Weight)
			if ticket < 0 {
				return member.Edges.StoragePolicy, nil
			}
		}
	}
	return nil, ErrNoAvailableChildren
}

func availableChild(member *ent.PolicyLoadBalance) bool {
	return member != nil && member.Weight > 0 && member.Edges.StoragePolicy != nil && member.Edges.StoragePolicy.Type != types.PolicyTypeLoadBalance
}
