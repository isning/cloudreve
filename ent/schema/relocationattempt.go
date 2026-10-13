package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Each external write has its own durable key and I/O completion evidence.
// Taking a new lease never overwrites compensation for an earlier attempt.
type RelocationAttempt struct{ ent.Schema }

func (RelocationAttempt) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Int("item_id").Positive().Immutable(),
		field.Int64("fence").Positive().Immutable(),
		field.Text("target_key").Immutable(),
		field.Enum("io_state").Values("not_started", "in_flight", "unknown", "ended").Default("not_started"),
		field.Bool("source_read_finished").Default(false),
		field.Int64("transferred_size").NonNegative().Default(0),
		field.Int64("verified_size").NonNegative().Default(0),
		field.String("verified_digest").Default(""),
		field.Bool("verified").Default(false),
		field.Enum("cleanup").Values("pending", "retained", "cleaned").Default("pending"),
		field.Text("error").Default(""),
	}
}

func (RelocationAttempt) Edges() []ent.Edge {
	return []ent.Edge{edge.From("item", RelocationItem.Type).Ref("attempts").Field("item_id").Unique().Required().Immutable()}
}

func (RelocationAttempt) Indexes() []ent.Index {
	return []ent.Index{index.Fields("item_id", "fence").Unique(), index.Fields("cleanup", "io_state")}
}
