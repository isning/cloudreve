package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// RelocationPlan marks a complete snapshot, including an empty selection. It
// survives task history deletion independently of the per-entity journal.
type RelocationPlan struct{ ent.Schema }

func (RelocationPlan) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Int("task_id").Positive().Unique().Immutable(),
		field.Int("owner_id").Positive().Immutable(),
		field.Int("destination_policy_id").Positive().Immutable(),
		field.JSON("file_ids", []int{}).Immutable(),
		field.Int("cleanup_task_id").NonNegative().Default(0),
	}
}
