package inventory

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/externalidentity"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"time"
)

// ResolveIdentity changes ownership only after explicit local and provider proof.
func (s *externalAuthStore) ResolveIdentity(ctx context.Context, id oidc.Identity, target int) (int, error) {
	ctx = externalAuthContext(ctx)
	if target == 0 {
		row, err := s.client.ExternalIdentity.Query().Where(externalidentity.IdentityKey(id.Key())).Only(ctx)
		if ent.IsNotFound(err) {
			return 0, oidc.ErrUnassociated
		}
		if err != nil {
			return 0, fmt.Errorf("cannot read external identity")
		}
		if row.State != externalidentity.StateBound || row.UserID == nil {
			return 0, fmt.Errorf("explicit association is required for this historical identity")
		}

		if row.Issuer != id.Issuer || row.Subject != id.Subject || row.ProviderID != id.ProviderID {
			return 0, fmt.Errorf("external identity namespace mismatch")
		}
		return *row.UserID, nil
	}
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return 0, fmt.Errorf("cannot begin identity association")
	}
	defer tx.Rollback()
	c := tx.Client()
	ctx = context.WithValue(ctx, TxCtx{}, &Tx{tx: tx})
	// Use the user row as the shared lifecycle lock, including unlink and deletion.
	_, err = c.User.Update().Where(user.ID(target), user.StatusEQ(user.StatusActive)).AddStorage(0).Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("association account is unavailable")
	}
	if _, err = c.User.Query().Where(user.ID(target), user.StatusEQ(user.StatusActive)).Only(ctx); err != nil {
		return 0, fmt.Errorf("association account is unavailable")
	}
	row, err := c.ExternalIdentity.Query().Where(externalidentity.IdentityKey(id.Key())).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return 0, fmt.Errorf("cannot read identity association")
	}
	if row != nil {
		if row.Issuer != id.Issuer || row.Subject != id.Subject || row.ProviderID != id.ProviderID {
			return 0, fmt.Errorf("external identity namespace mismatch")
		}
		if row.State == externalidentity.StateDeleted {
			return 0, fmt.Errorf("deleted external identity cannot be associated")
		}
		if row.UserID != nil && *row.UserID != target {
			return 0, fmt.Errorf("external identity is already associated with another account")
		}
		if _, err = c.ExternalIdentity.UpdateOne(row).SetUserID(target).SetState(externalidentity.StateBound).SetLinkedAt(time.Now().UTC()).Save(ctx); err != nil {
			return 0, fmt.Errorf("account already has an identity for this provider")
		}
	} else {
		if _, err = c.ExternalIdentity.Create().SetIdentityKey(id.Key()).SetProviderID(id.ProviderID).SetIssuer(id.Issuer).SetSubject(id.Subject).SetUserID(target).Save(ctx); err != nil {
			return 0, fmt.Errorf("identity or account provider association conflicts")
		}
	}
	if err := RecordAudit(ctx, c, AuditEvent{Type: types.AuditLinkAccount, User: &ent.User{ID: target}, Content: types.LogEntry{OpenIDProvider: &id.ProviderID, Sub: id.Subject, AccountID: target}}); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("cannot commit identity association")
	}
	return target, nil
}
