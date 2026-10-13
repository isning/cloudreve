// Package storagepolicy owns current-account destination authorization and
// automatic write placement, independently of an entity's physical location.
package storagepolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
)

var ErrNoAvailablePolicies = errors.New("no available storage policies")
var ErrPolicyNotGranted = errors.New("storage policy is not granted to current owner")

type Resolver struct {
	users    inventory.UserClient
	policies inventory.StoragePolicyClient
}

func New(users inventory.UserClient, policies inventory.StoragePolicyClient) *Resolver {
	return &Resolver{users: users, policies: policies}
}

// Available reloads the owner's group instead of trusting a navigation snapshot.
// It returns only destinations for new writes; existing entity reads retain
// their own storage policy and do not depend on this list.
func (r *Resolver) Available(ctx context.Context, ownerID int) ([]*ent.StoragePolicy, error) {
	u, _ := inventory.InheritTx(ctx, r.users)
	owner, err := u.GetByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	if err != nil {
		return nil, fmt.Errorf("load current policy owner: %w", err)
	}
	if owner.Edges.Group == nil {
		return nil, fmt.Errorf("owner group not loaded")
	}
	sc, _ := inventory.InheritTx(ctx, r.policies)
	policies, err := sc.AvailableByGroup(ctx, owner.Edges.Group)
	if err != nil {
		return nil, fmt.Errorf("load available storage policies: %w", err)
	}
	return policies, nil
}

func (r *Resolver) Default(ctx context.Context, ownerID int) (*ent.StoragePolicy, error) {
	return r.Select(ctx, ownerID, 0, 0)
}

// Select authorizes explicit destinations before returning them. A stale
// automatic preference falls directly back to the current first grant.
func (r *Resolver) Select(ctx context.Context, ownerID, explicitID, preferenceID int) (*ent.StoragePolicy, error) {
	policies, err := r.Available(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	if explicitID != 0 {
		for _, policy := range policies {
			if policy.ID == explicitID {
				return policy, nil
			}
		}
		return nil, ErrPolicyNotGranted
	}
	if len(policies) == 0 {
		return nil, ErrNoAvailablePolicies
	}
	for _, policy := range policies {
		if policy.ID == preferenceID {
			return policy, nil
		}
	}
	return policies[0], nil
}
