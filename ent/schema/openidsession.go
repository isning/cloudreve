package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type OpenIDSession struct{ ent.Schema }

func (OpenIDSession) Fields() []ent.Field {
	return []ent.Field{
		field.String("root_id").MaxLen(36).Unique(),
		field.Int("user_id").Optional().Nillable(),
		field.Int("provider_id"),
		field.String("issuer").MaxLen(2048),
		field.Time("expires_at").SchemaType(map[string]string{dialect.MySQL: "datetime"}),
		field.Time("revoked_at").Optional().Nillable().SchemaType(map[string]string{dialect.MySQL: "datetime"}),
		field.Bytes("payload").Optional().Sensitive(),
	}
}
func (OpenIDSession) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("openid_sessions").Field("user_id").Unique(),
	}
}
func (OpenIDSession) Indexes() []ent.Index {
	return []ent.Index{index.Fields("expires_at"), index.Fields("user_id")}
}
