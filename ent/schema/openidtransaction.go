package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type OpenIDTransaction struct{ ent.Schema }

func (OpenIDTransaction) Fields() []ent.Field {
	return []ent.Field{
		field.String("transaction_key").MaxLen(64).Unique(),
		field.Enum("kind").Values("auth", "pending_mfa"),
		field.Int("provider_id"),
		field.Int("user_id").Optional().Nillable(),
		field.String("browser_proof").MaxLen(64).Sensitive(),
		field.String("config_digest").MaxLen(64),
		field.Time("expires_at").SchemaType(map[string]string{dialect.MySQL: "datetime"}),
		field.Int("attempts").Default(0),
		field.Bool("consumed").Default(false),
		field.Bytes("payload").Sensitive(),
	}
}
func (OpenIDTransaction) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("openid_transactions").Field("user_id").Unique(),
	}
}
func (OpenIDTransaction) Indexes() []ent.Index {
	return []ent.Index{index.Fields("expires_at"), index.Fields("user_id")}
}
