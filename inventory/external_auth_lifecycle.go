package inventory

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/externalidentity"
	"github.com/cloudreve/Cloudreve/v4/ent/openidsession"
	"github.com/cloudreve/Cloudreve/v4/ent/openidtransaction"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"time"
)

func detachExternalAuth(ctx context.Context, c *ent.Client, uid int) error {
	ctx = externalAuthContext(ctx)
	if _, err := c.ExternalIdentity.Update().Where(externalidentity.UserID(uid)).ClearUserID().SetState(externalidentity.StateDeleted).Save(ctx); err != nil {
		return fmt.Errorf("cannot seal deleted external identities")
	}
	if _, err := c.OpenIDTransaction.Update().Where(openidtransaction.UserID(uid)).ClearUserID().SetConsumed(true).SetPayload([]byte{}).Save(ctx); err != nil {
		return fmt.Errorf("cannot invalidate external authentication transactions")
	}
	if _, err := c.OpenIDSession.Update().Where(openidsession.UserID(uid)).ClearUserID().SetRevokedAt(time.Now().UTC()).ClearPayload().Save(ctx); err != nil {
		return fmt.Errorf("cannot revoke deleted external sessions")
	}
	return nil
}
func (s *externalAuthStore) Cleanup(ctx context.Context, now time.Time) error {
	ctx = externalAuthContext(ctx)
	if _, err := s.client.OpenIDTransaction.Delete().Where(openidtransaction.ExpiresAtLTE(now.UTC())).Exec(ctx); err != nil {
		return fmt.Errorf("cannot clean expired authentication transactions")
	}
	// Revocation markers remain until the maximum issued refresh expiry.
	if _, err := s.client.OpenIDSession.Delete().Where(openidsession.ExpiresAtLTE(now.UTC())).Exec(ctx); err != nil {
		return fmt.Errorf("cannot clean expired external sessions")
	}
	return nil
}
func ReleaseManagedAccount(ctx context.Context, c *ent.Client, uid int) error {
	n, err := c.User.Update().Where(user.ID(uid)).SetSSOManaged(false).Save(externalAuthContext(ctx))
	if err != nil {
		return fmt.Errorf("cannot release managed account")
	}
	if n == 0 {
		row, err := c.User.Get(externalAuthContext(ctx), uid)
		if err != nil || row.SSOManaged {
			return fmt.Errorf("cannot release managed account")
		}
	}
	return nil
}
