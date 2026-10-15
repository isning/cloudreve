package inventory

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent/externalidentity"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"strconv"
)

func (s *externalAuthStore) Bindings(ctx context.Context, uid int) ([]oidc.Binding, error) {
	rows, err := s.client.ExternalIdentity.Query().Where(externalidentity.UserID(uid), externalidentity.StateEQ(externalidentity.StateBound)).All(externalAuthContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("cannot read identity associations")
	}
	result := []oidc.Binding{}
	for _, row := range rows {
		result = append(result, oidc.Binding{Provider: row.ProviderID, LinkedAt: row.LinkedAt, Issuer: row.Issuer})
	}
	return result, nil
}
func (s *externalAuthStore) UnlinkIdentity(ctx context.Context, uid, provider int, usable map[string]bool) error {
	ctx = externalAuthContext(ctx)
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("cannot begin identity removal")
	}
	defer tx.Rollback()
	c := tx.Client()
	ctx = context.WithValue(ctx, TxCtx{}, &Tx{tx: tx})
	_, err = c.User.Update().Where(user.ID(uid), user.StatusEQ(user.StatusActive)).AddStorage(0).Save(ctx)
	if err != nil {
		return fmt.Errorf("account is unavailable")
	}
	u, err := c.User.Query().Where(user.ID(uid), user.StatusEQ(user.StatusActive)).Only(ctx)
	if err != nil {
		return fmt.Errorf("account is unavailable")
	}
	row, err := c.ExternalIdentity.Query().Where(externalidentity.UserID(uid), externalidentity.ProviderID(provider), externalidentity.StateEQ(externalidentity.StateBound)).Only(ctx)
	if err != nil {
		return fmt.Errorf("association is unavailable")
	}
	if u.SSOManaged && usable[strconv.Itoa(row.ProviderID)+":"+row.Issuer] {
		bound, err := c.ExternalIdentity.Query().Where(externalidentity.UserID(uid), externalidentity.StateEQ(externalidentity.StateBound)).All(ctx)
		if err != nil {
			return fmt.Errorf("cannot check remaining associations")
		}
		remaining := 0
		for _, other := range bound {
			if other.ID != row.ID && usable[strconv.Itoa(other.ProviderID)+":"+other.Issuer] {
				remaining++
			}
		}
		if remaining == 0 {
			return fmt.Errorf("cannot remove the managed account's last usable external identity")
		}
	}
	if err = c.ExternalIdentity.UpdateOne(row).ClearUserID().SetState(externalidentity.StateUnlinked).Exec(ctx); err != nil {
		return fmt.Errorf("cannot remove identity association")
	}
	if err := RecordAudit(ctx, c, AuditEvent{Type: types.AuditUnlinkAccount, Content: types.LogEntry{OpenIDProvider: &provider, Sub: row.Subject, AccountID: uid}}); err != nil {
		return err
	}
	return tx.Commit()
}
