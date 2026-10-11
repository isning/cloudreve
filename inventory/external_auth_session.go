package inventory

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent/openidsession"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"time"
)

func (s *externalAuthStore) CreateSession(ctx context.Context, session oidc.Session) error {
	return s.client.OpenIDSession.Create().SetRootID(session.RootID).SetUserID(session.UserID).SetProviderID(session.ProviderID).SetIssuer(session.Issuer).SetExpiresAt(session.ExpiresAt.UTC()).SetPayload(session.Payload).Exec(externalAuthContext(ctx))
}
func (s *externalAuthStore) Session(ctx context.Context, root string) (oidc.Session, error) {
	row, err := s.client.OpenIDSession.Query().Where(openidsession.RootID(root)).Only(externalAuthContext(ctx))
	if err != nil {
		return oidc.Session{}, fmt.Errorf("external root session is unavailable")
	}
	uid := 0
	if row.UserID != nil {
		uid = *row.UserID
	}
	return oidc.Session{RootID: row.RootID, UserID: uid, ProviderID: row.ProviderID, Issuer: row.Issuer, ExpiresAt: row.ExpiresAt, Revoked: row.RevokedAt != nil, Payload: row.Payload}, nil
}
func (s *externalAuthStore) TouchSession(ctx context.Context, session oidc.Session, expires, now time.Time) error {
	ctx = externalAuthContext(ctx)
	for attempt := 0; attempt < 5; attempt++ {
		current, err := s.Session(ctx, session.RootID)
		if err != nil || current.UserID != session.UserID || current.Revoked || !current.ExpiresAt.After(now) {
			return fmt.Errorf("external session is expired or revoked")
		}
		if !expires.After(current.ExpiresAt) {
			return nil
		}
		n, err := s.client.OpenIDSession.Update().Where(openidsession.RootID(current.RootID), openidsession.UserID(current.UserID), openidsession.RevokedAtIsNil(), openidsession.ExpiresAtEQ(current.ExpiresAt.UTC())).SetExpiresAt(expires.UTC()).Save(ctx)
		if err != nil {
			return fmt.Errorf("cannot extend external root session")
		}
		if n == 1 {
			return nil
		}
	}
	return fmt.Errorf("external session changed; retry refresh")
}
func (s *externalAuthStore) RevokeSession(ctx context.Context, session oidc.Session, now time.Time) error {
	n, err := s.client.OpenIDSession.Update().Where(openidsession.RootID(session.RootID), openidsession.UserID(session.UserID)).SetRevokedAt(now.UTC()).ClearPayload().Save(externalAuthContext(ctx))
	if err == nil && n == 0 {
		current, readErr := s.Session(ctx, session.RootID)
		if readErr == nil && current.UserID == session.UserID && current.Revoked {
			return nil
		}
	}
	if err != nil || n != 1 {
		return fmt.Errorf("cannot revoke external root session")
	}
	return nil
}
