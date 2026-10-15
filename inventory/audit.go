package inventory

import (
	"context"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// AuditEvent carries only domain identifiers and an allowlisted description.
type AuditEvent struct {
	Type                      types.AuditEvent
	User                      *ent.User
	FileID, EntityID, ShareID int
	Content                   types.LogEntry
}

// AuditRecorder binds writes to transactions owned by inventory implementations.
type AuditRecorder interface {
	Record(context.Context, AuditEvent) error
	WithClient(*ent.Client) AuditRecorder
}
type auditRecorderKey struct{}

func WithAuditRecorder(ctx context.Context, recorder AuditRecorder) context.Context {
	return context.WithValue(ctx, auditRecorderKey{}, recorder)
}
func AuditRecorderFromContext(ctx context.Context) AuditRecorder {
	r, _ := ctx.Value(auditRecorderKey{}).(AuditRecorder)
	return r
}
func RecordAudit(ctx context.Context, client *ent.Client, event AuditEvent) error {
	if r := AuditRecorderFromContext(ctx); r != nil {
		return r.WithClient(client).Record(ctx, event)
	}
	return nil
}

func auditMutation[T TxOperator, R any](ctx context.Context, client T, mutate func(context.Context, T) (R, []AuditEvent, error)) (R, error) {
	if AuditRecorderFromContext(ctx) == nil {
		result, _, err := mutate(ctx, client)
		return result, err
	}
	var zero R
	c, tx, ctx, err := WithTx(ctx, client)
	if err != nil {
		return zero, err
	}
	defer Rollback(tx)
	result, events, err := mutate(ctx, c)
	if err != nil {
		return zero, err
	}
	for _, event := range events {
		if err := RecordAudit(ctx, c.GetClient(), event); err != nil {
			return zero, err
		}
	}
	if err := Commit(tx); err != nil {
		return zero, err
	}
	return result, nil
}

func (c *userClient) mutateWithAudit(ctx context.Context, u *ent.User, kind types.AuditEvent, content types.LogEntry, mutate func(context.Context, *ent.Client) (*ent.User, error)) (*ent.User, error) {
	if AuditRecorderFromContext(ctx) == nil {
		return mutate(ctx, c.client)
	}
	uc, tx, ctx, err := WithTx(ctx, c)
	if err != nil {
		return nil, err
	}
	defer Rollback(tx)
	result, err := mutate(ctx, uc.client)
	if err != nil {
		return result, err
	}
	actor := UserFromContext(ctx)
	if actor == nil || IsAnonymousUser(actor) {
		actor = result
	}
	content.AccountID = result.ID
	if err := RecordAudit(ctx, uc.client, AuditEvent{Type: kind, User: actor, Content: content}); err != nil {
		return nil, err
	}
	if kind == types.AuditUserChanged && u != nil && u.ID > 0 && u.GroupUsers != result.GroupUsers {
		if err := RecordAudit(ctx, uc.client, AuditEvent{Type: types.AuditGroupChanged, User: actor, Content: types.LogEntry{AccountID: result.ID, GroupIDFrom: u.GroupUsers, GroupID: result.GroupUsers}}); err != nil {
			return nil, err
		}
	}
	if err := Commit(tx); err != nil {
		return nil, err
	}
	return result, nil
}
