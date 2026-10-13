package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"time"
)

// Only migration I/O participates; ordinary download URLs have no global lease.
// A process crash cannot manufacture evidence that an unfinished read ended.
type StorageObjectReader struct{ ent.Schema }

func (StorageObjectReader) Fields() []ent.Field {
	return []ent.Field{
		field.String("location_key").MaxLen(64).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Bool("finished").Default(false),
	}
}
func (StorageObjectReader) Indexes() []ent.Index {
	return []ent.Index{index.Fields("location_key", "finished")}
}
