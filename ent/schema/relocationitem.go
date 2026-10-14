package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// RelocationItem survives task history and account deletion: its integer source
// identities have no cascading foreign keys to those short-lived records.
type RelocationItem struct{ ent.Schema }

func (RelocationItem) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Int("task_id").Positive().Immutable(),
		field.Int("owner_id").Positive().Immutable(),
		field.Int("source_entity_id").Positive().Immutable(),
		field.Int("source_policy_id").Positive().Immutable(),
		field.Text("source_key").Immutable(),
		field.String("source_location").Immutable(),
		field.Int("destination_policy_id").Positive().Immutable(),
		field.String("destination_location").Immutable(),
		field.JSON("snapshot", &types.RelocationSnapshot{}).Immutable(),
		field.JSON("references", []types.RelocationReference{}).Immutable(),
		field.Enum("state").Values("planned", "copying", "verified", "committed", "noop", "failed").Default("planned"),
		field.Int64("fence").NonNegative().Default(0),
		field.String("lease_owner").Default(""),
		field.Time("lease_until").Optional().Nillable(),
		field.Int("active_attempt_id").Optional(),
		field.Int("target_entity_id").Optional(),
		field.Bool("source_read_finished").Default(false),
		field.Enum("source_cleanup").Values("pending", "retained", "cleaned", "unneeded").Default("pending"),
		field.Text("error").Default(""),
	}
}

func (RelocationItem) Edges() []ent.Edge {
	return []ent.Edge{edge.To("attempts", RelocationAttempt.Type)}
}

func (RelocationItem) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("task_id", "source_entity_id").Unique(),
		index.Fields("source_policy_id", "source_cleanup"),
		index.Fields("destination_policy_id", "state"),
		index.Fields("state", "lease_until"),
	}
}
