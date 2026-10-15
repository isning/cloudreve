package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// AuditLog preserves historical object identifiers without foreign keys so
// deleting an account, file or blob cannot remove its audit trail.
type AuditLog struct{ ent.Schema }

func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.Int("type").NonNegative().Max(61).Immutable(),
		field.String("correlation_id").MaxLen(64).Default("").Immutable(),
		field.String("ip").MaxLen(64).Default("").Immutable(),
		field.Int("user_id").NonNegative().Default(0).Immutable(),
		field.Int("file_id").NonNegative().Default(0).Immutable(),
		field.Int("entity_id").NonNegative().Default(0).Immutable(),
		field.Int("share_id").NonNegative().Default(0).Immutable(),
		field.JSON("content", &types.LogEntry{}).Immutable(),
	}
}

func (AuditLog) Mixin() []ent.Mixin { return []ent.Mixin{CommonMixin{}} }

func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("file_id", "id"),
		index.Fields("user_id", "id"),
		index.Fields("type", "id"),
		index.Fields("correlation_id"),
		index.Fields("created_at", "id"),
	}
}
