package inventory

import (
	"context"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
)

// Project canonical grants into the existing administration response. The Ent
// groups edge describes only the default and cannot represent all assignments.
// Loading all requested policies together keeps list queries bounded per page.
func (c *storagePolicyClient) loadPolicyGroups(ctx context.Context, policies []*ent.StoragePolicy) error {
	load, _ := ctx.Value(LoadStoragePolicyGroup{}).(bool)
	if !load || len(policies) == 0 {
		return nil
	}
	ids := make([]int, 0, len(policies))
	byID := make(map[int]*ent.StoragePolicy, len(policies))
	for _, policy := range policies {
		ids = append(ids, policy.ID)
		byID[policy.ID] = policy
		policy.Edges.Groups = nil
	}
	grants, err := c.client.GroupPolicy.Query().Where(
		grouppolicy.StoragePolicyIDIn(ids...), grouppolicy.HasGroupWith(group.DeletedAtIsNil()),
	).Order(ent.Asc(grouppolicy.FieldGroupID)).WithGroup().All(ctx)
	if err != nil {
		return fmt.Errorf("load storage policy groups: %w", err)
	}
	for _, grant := range grants {
		if grant.Edges.Group != nil {
			policy := byID[grant.StoragePolicyID]
			policy.Edges.Groups = append(policy.Edges.Groups, grant.Edges.Group)
		}
	}
	return nil
}
