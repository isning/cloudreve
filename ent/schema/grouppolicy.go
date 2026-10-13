package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// GroupPolicy is an ordered destination grant. Removed grants are deleted,
// rather than retained as soft-deleted authorization records.
type GroupPolicy struct{ ent.Schema }

func (GroupPolicy) Fields() []ent.Field {
	return []ent.Field{
		field.Int("group_id"),
		field.Int("storage_policy_id"),
		field.Int("position").NonNegative(),
	}
}

func (GroupPolicy) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("group", Group.Type).Ref("policy_assignments").Field("group_id").Unique().Required(),
		edge.From("storage_policy", StoragePolicy.Type).Ref("group_assignments").Field("storage_policy_id").Unique().Required(),
	}
}

func (GroupPolicy) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "storage_policy_id").Unique(),
		index.Fields("group_id", "position").Unique(),
	}
}
