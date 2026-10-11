package inventory

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/openidtransaction"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"time"
)

type externalAuthStore struct{ client *ent.Client }

func NewExternalAuthStore(client *ent.Client) oidc.Store { return &externalAuthStore{client} }
func externalAuthContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, debug.SkipDbLogging{}, true)
}
func (s *externalAuthStore) PutTransaction(ctx context.Context, t oidc.Transaction) error {
	q := s.client.OpenIDTransaction.Create().SetTransactionKey(t.Key).SetKind(openidtransaction.Kind(t.Kind)).SetProviderID(t.ProviderID).SetBrowserProof(t.BrowserProof).SetConfigDigest(t.ConfigDigest).SetExpiresAt(t.ExpiresAt.UTC()).SetPayload(t.Payload)
	if t.UserID > 0 {
		q.SetUserID(t.UserID)
	}
	return q.Exec(externalAuthContext(ctx))
}
func (s *externalAuthStore) Transaction(ctx context.Context, key string) (oidc.Transaction, error) {
	t, err := s.client.OpenIDTransaction.Query().Where(openidtransaction.TransactionKey(key), openidtransaction.Consumed(false)).Only(externalAuthContext(ctx))
	if err != nil {
		return oidc.Transaction{}, fmt.Errorf("authentication transaction is unavailable")
	}
	uid := 0
	if t.UserID != nil {
		uid = *t.UserID
	}
	return oidc.Transaction{Key: t.TransactionKey, Kind: string(t.Kind), ProviderID: t.ProviderID, UserID: uid, BrowserProof: t.BrowserProof, ConfigDigest: t.ConfigDigest, ExpiresAt: t.ExpiresAt, Payload: t.Payload}, nil
}
func (s *externalAuthStore) Consume(ctx context.Context, t oidc.Transaction, now time.Time) error {
	n, err := s.client.OpenIDTransaction.Update().Where(openidtransaction.TransactionKey(t.Key), openidtransaction.KindEQ(openidtransaction.Kind(t.Kind)), openidtransaction.BrowserProof(t.BrowserProof), openidtransaction.ConfigDigest(t.ConfigDigest), openidtransaction.ExpiresAtGT(now.UTC()), openidtransaction.Consumed(false)).SetConsumed(true).SetPayload([]byte{}).Save(externalAuthContext(ctx))
	if err != nil || n != 1 {
		return fmt.Errorf("authentication transaction expired or was already consumed")
	}
	return nil
}

func (s *externalAuthStore) ReserveAttempt(ctx context.Context, t oidc.Transaction, now time.Time) error {
	n, err := s.client.OpenIDTransaction.Update().Where(openidtransaction.TransactionKey(t.Key), openidtransaction.KindEQ(openidtransaction.KindPendingMfa), openidtransaction.Consumed(false), openidtransaction.BrowserProof(t.BrowserProof), openidtransaction.ExpiresAtGT(now.UTC()), openidtransaction.AttemptsLT(5)).AddAttempts(1).Save(externalAuthContext(ctx))
	if err != nil || n != 1 {
		return fmt.Errorf("second factor challenge expired or too many attempts")
	}
	return nil
}
