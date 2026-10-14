package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// A durable physical-location gate shared by alias admission and object deletion.
// It deliberately has no account, Task or Entity cascade.
type StorageObject struct{ ent.Schema }

func (StorageObject) Fields() []ent.Field {
	return []ent.Field{
		field.String("key").MaxLen(64).Unique().Immutable(),
		field.Int64("generation").Default(0),
		field.Bool("retired").Default(false),
	}
}
