package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
)

var ErrInvalidGroupPolicies = errors.New("invalid group storage policy assignment")

func (c *groupClient) UpsertWithPolicies(ctx context.Context, input *ent.Group, requested *[]int, legacyDefault *int) (*ent.Group, error) {
	gc, tx, ctx, err := WithTx(ctx, c)
	if err != nil {
		return nil, err
	}
	defer Rollback(tx)
	defaultID := 0
	var ids []int
	if input.ID > 0 {
		stored, err := gc.GetByID(ctx, input.ID)
		if err != nil {
			return nil, err
		}
		defaultID = stored.StoragePolicyID
		grants, err := gc.client.GroupPolicy.Query().Where(grouppolicy.GroupID(input.ID)).Order(ent.Asc(grouppolicy.FieldPosition)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			ids = append(ids, g.StoragePolicyID)
		}
	}
	writeGrants := requested != nil
	if requested != nil {
		ids = append([]int(nil), (*requested)...)
		if len(ids) == 0 {
			return nil, ErrInvalidGroupPolicies
		}
		defaultID = ids[0]
		if legacyDefault != nil && *legacyDefault != defaultID {
			return nil, fmt.Errorf("%w: default must match first policy", ErrInvalidGroupPolicies)
		}
	} else if legacyDefault != nil {
		if *legacyDefault == 0 && len(ids) > 0 {
			return nil, fmt.Errorf("%w: cannot clear default while grants remain", ErrInvalidGroupPolicies)
		}
		defaultID = *legacyDefault
		if len(ids) > 0 && ids[0] != defaultID {
			next := []int{defaultID}
			for _, id := range ids {
				if id != defaultID {
					next = append(next, id)
				}
			}
			ids = next
			writeGrants = true
		}
	}
	validate := ids
	if len(validate) == 0 && defaultID > 0 {
		validate = []int{defaultID}
	}
	seen := make(map[int]bool, len(validate))
	for _, id := range validate {
		if id <= 0 || seen[id] {
			return nil, ErrInvalidGroupPolicies
		}
		seen[id] = true
	}
	if defaultID < 0 {
		return nil, ErrInvalidGroupPolicies
	}
	if len(validate) > 0 {
		count, err := gc.client.StoragePolicy.Query().Where(storagepolicy.IDIn(validate...)).Count(ctx)
		if err != nil {
			return nil, err
		}
		if count != len(validate) {
			return nil, ErrInvalidGroupPolicies
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
		if _, err := gc.client.GroupPolicy.Delete().Where(grouppolicy.GroupID(result.ID)).Exec(ctx); err != nil {
			return nil, err
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
