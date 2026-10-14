// Package storagepolicy owns current-account destination authorization and
// automatic write placement, independently of an entity's physical location.
package storagepolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
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

// SelectForFile reads current preference ancestry from Ent. Navigation caches
// carry paths and display data, and are never the authority for placement.
func (r *Resolver) SelectForFile(ctx context.Context, ownerID, explicitID int, files inventory.FileClient, fileID int) (*ent.StoragePolicy, error) {
	if explicitID != 0 {
		return r.Select(ctx, ownerID, explicitID, 0)
	}
	fc, _ := inventory.InheritTx(ctx, files)
	seen := make(map[int]bool)
	preference := 0
	for fileID > 0 {
		if seen[fileID] {
			return nil, fmt.Errorf("storage preference ancestry has a cycle")
		}
		seen[fileID] = true
		file, err := fc.GetByID(ctx, fileID)
		if err != nil {
			return nil, fmt.Errorf("load storage preference ancestry: %w", err)
		}
		if file.OwnerID != ownerID {
			return nil, fmt.Errorf("storage preference owner mismatch")
		}
		if file.FileChildren == 0 {
			break
		}
		if file.StoragePolicyFiles > 0 {
			preference = file.StoragePolicyFiles
			break
		}
		fileID = file.FileChildren
	}
	return r.Select(ctx, ownerID, 0, preference)
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
			// Pro clients may explicitly upload to any child of a granted pool,
			// including children whose automatic selection weight is zero.
			if policy.Type == types.PolicyTypeLoadBalance {
				for _, member := range policy.Edges.PolicyLoadBalance {
					if member.Edges.StoragePolicy != nil && member.StoragePolicyID == explicitID {
						return member.Edges.StoragePolicy, nil
					}
				}
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
		if policy.Type == types.PolicyTypeLoadBalance {
			for _, member := range policy.Edges.PolicyLoadBalance {
				if member.Edges.StoragePolicy != nil && member.StoragePolicyID == preferenceID {
					return member.Edges.StoragePolicy, nil
				}
			}
		}
	}
	return policies[0], nil
}

// ResolveForFile authorizes the logical preference and selects one concrete
// destination. Callers persist that destination in the upload session or task;
// subsequent chunks and retries must never draw again.
func (r *Resolver) ResolveForFile(ctx context.Context, ownerID, explicitID int, files inventory.FileClient, fileID int) (*ent.StoragePolicy, error) {
	policy, err := r.SelectForFile(ctx, ownerID, explicitID, files, fileID)
	if err != nil {
		return nil, err
	}
	return Choose(policy)
}
