package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"time"
)

type ExternalIdentity struct{ ent.Schema }

func (ExternalIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.String("identity_key").MaxLen(64).Unique(),
		field.Int("provider_id"),
		field.String("issuer").MaxLen(2048),
		field.String("subject").MaxLen(2048).Sensitive(),
		field.Int("user_id").Optional().Nillable(),
		field.Enum("state").Values("bound", "unlinked", "deleted").Default("bound"),
		field.Time("linked_at").Default(time.Now).SchemaType(map[string]string{dialect.MySQL: "datetime"}),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now).SchemaType(map[string]string{dialect.MySQL: "datetime"}),
	}
}
func (ExternalIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("external_identities").Field("user_id").Unique(),
	}
}
func (ExternalIdentity) Indexes() []ent.Index {
	return []ent.Index{index.Fields("user_id", "provider_id").Unique()}
}
