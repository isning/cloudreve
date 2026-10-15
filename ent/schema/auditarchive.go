package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuditArchive tracks an expiring, authenticated export independently of a
// replica's local filesystem. Only successfully streamed rows can be purged.
type AuditArchive struct{ ent.Schema }

func (AuditArchive) Fields() []ent.Field {
	return []ent.Field{
		field.String("archive_key").MaxLen(36).Unique().Immutable(),
		field.Int("owner_id").Positive().Immutable(),
		field.String("token_hash").MaxLen(64).Immutable().Sensitive(),
		field.Time("not_before").Immutable(),
		field.Time("not_after").Immutable(),
		field.JSON("categories", []int{}).Immutable(),
		field.Int("high_id").NonNegative().Immutable(),
		field.String("status").Default("pending"),
		field.Time("expires").Immutable(),
	}
}
func (AuditArchive) Mixin() []ent.Mixin   { return []ent.Mixin{CommonMixin{}} }
func (AuditArchive) Indexes() []ent.Index { return []ent.Index{index.Fields("expires")} }
