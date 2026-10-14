package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PolicyLoadBalance assigns a concrete storage policy to a weighted pool.
// The field and edge names match the public Pro administration client.
type PolicyLoadBalance struct{ ent.Schema }

func (PolicyLoadBalance) Fields() []ent.Field {
	return []ent.Field{
		field.Int("load_balance_id"),
		field.Int("storage_policy_id"),
		field.Int("weight").Default(1).NonNegative().Max(9007199254740991),
	}
}

func (PolicyLoadBalance) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("load_balance", StoragePolicy.Type).Ref("policy_load_balance").Field("load_balance_id").Unique().Required(),
		edge.From("storage_policy", StoragePolicy.Type).Ref("load_balance_memberships").Field("storage_policy_id").Unique().Required(),
	}
}

func (PolicyLoadBalance) Indexes() []ent.Index {
	return []ent.Index{index.Fields("load_balance_id", "storage_policy_id").Unique()}
}
