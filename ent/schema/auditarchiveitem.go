package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuditArchiveItem preserves exact export membership across replicas, restarts
// and concurrent writes; log deletion does not cascade into this evidence.
type AuditArchiveItem struct{ ent.Schema }

func (AuditArchiveItem) Fields() []ent.Field {
	return []ent.Field{
		field.String("archive_id").MaxLen(36).Immutable(),
		field.Int("log_id").Positive().Immutable(),
	}
}
func (AuditArchiveItem) Indexes() []ent.Index {
	return []ent.Index{index.Fields("archive_id", "log_id").Unique()}
}
