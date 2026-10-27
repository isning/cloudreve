// Package storagepolicy owns current-account destination authorization and
// automatic write placement, independently of an entity's physical location.
package storagepolicy

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
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

// Available inherits the file transaction, including SQLite's sole connection.
// For MySQL's older read view, base clients supply committed planning metadata;
// Revalidate still checks the accepting write inside its original transaction.
// Existing entity reads do not depend on this list.
func (r *Resolver) Available(ctx context.Context, ownerID int) ([]*ent.StoragePolicy, error) {
	// This list is planning metadata. A base-client authorization lock would
	// wait on the accepting transaction's owner fence; Revalidate uses that tx.
	ctx = context.WithValue(ctx, inventory.CurrentPermissionReadCtx{}, false)
	u, tx := inventory.InheritTx(ctx, r.users)
	sc, _ := inventory.InheritTx(ctx, r.policies)
	// Inspect the inherited query's dialect without borrowing another connection.
	usesMySQL := false
	owner, err := u.GetClient().User.Query().Where(user.ID(ownerID), func(s *sql.Selector) {
		usesMySQL = s.Dialect() == dialect.MySQL
	}).WithGroup().Only(ctx)
	if usesMySQL && tx != nil && (err == nil || ent.IsNotFound(err)) {
		metadata := inventory.CommittedMetadataClient(ctx)
		u = r.users.SetClient(metadata).(inventory.UserClient)
		sc = r.policies.SetClient(metadata).(inventory.StoragePolicyClient)
		owner, err = u.GetByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	}
	if err != nil {
		return nil, fmt.Errorf("load current policy owner: %w", err)
	}
	if owner.Edges.Group == nil {
		return nil, fmt.Errorf("owner group not loaded")
	}
	policies, err := sc.AvailableByGroup(ctx, owner.Edges.Group)
	if err != nil {
		return nil, fmt.Errorf("load available storage policies: %w", err)
	}
	return policies, nil
}

func (r *Resolver) Default(ctx context.Context, ownerID int) (*ent.StoragePolicy, error) {
	return r.Select(ctx, ownerID, 0, 0)
}

// Revalidate is the final grant check for a write. The caller's transaction must
// already hold the owner lock followed by the chosen concrete policy lock. Select
// provides placement metadata; its ordinary reads can retain an older snapshot.
// A nonzero poolID requires this exact pool-to-destination binding, in the same
// query as its grant. Separate checks can lock different grants in reverse order
// when administrators change memberships between selection and acceptance.
func (r *Resolver) Revalidate(ctx context.Context, ownerID, policyID, poolID int) error {
	sc, _ := inventory.InheritTx(ctx, r.policies)
	granted, err := inventory.StoragePolicyGranted(ctx, sc.GetClient(), ownerID, policyID, poolID)
	if err != nil {
		return fmt.Errorf("revalidate storage policy grant: %w", err)
	}
	if !granted {
		return ErrPolicyNotGranted
	}
	return nil
}

// SelectForFile reads preference ancestry from Ent. Accepting writes enable
// CurrentPermissionReadCtx after their owner fence; navigation caches are never
// the authority for placement.
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
