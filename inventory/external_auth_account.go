package inventory

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"strings"
)

func (s *externalAuthStore) CreateIdentityAccount(ctx context.Context, id oidc.Identity, profile oidc.Profile) (int, error) {
	ctx = externalAuthContext(ctx)
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return 0, fmt.Errorf("cannot begin external account creation")
	}
	defer tx.Rollback()
	c := tx.Client()
	// Configuration was validated when saved, but the target group can disappear
	// before this login. Check it again inside account creation on every dialect.
	if _, err := c.Group.Get(ctx, profile.GroupID); err != nil {
		return 0, fmt.Errorf("initial account group is unavailable")
	}
	// The identity insert and user creation share one transaction. Neither a
	// bootstrap administrator nor an email-based reassignment is permitted.
	u, err := NewUserClient(c).Create(ctx, &NewUserArgs{Email: strings.ToLower(profile.Email), Nick: profile.Name, Avatar: profile.Avatar, GroupID: profile.GroupID, Status: user.StatusActive, SSOManaged: true, SkipBootstrap: true})
	if err != nil {
		return 0, fmt.Errorf("email is unavailable; create a local account and associate this identity explicitly")
	}
	if err = c.ExternalIdentity.Create().SetIdentityKey(id.Key()).SetProviderID(id.ProviderID).SetIssuer(id.Issuer).SetSubject(id.Subject).SetUserID(u.ID).Exec(ctx); err != nil {
		return 0, fmt.Errorf("external identity association conflicts; restart authentication")
	}
	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("cannot commit external account creation")
	}
	return u.ID, nil
}
