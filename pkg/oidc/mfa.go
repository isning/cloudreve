package oidc

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"time"
)

type mfaPayload struct {
	Provider Provider
	IDToken  string
}
type mfaProofContext struct{}

// WithBrowserProof carries transport-owned proof without coupling the protocol to HTTP.
func WithBrowserProof(ctx context.Context, proof string) context.Context {
	return context.WithValue(ctx, mfaProofContext{}, proof)
}
func (r *Runtime) prepareMFA(ctx context.Context, uid int, p Provider, idToken string) (*FinishResult, error) {
	proof, _ := ctx.Value(mfaProofContext{}).(string)
	if proof == "" {
		return nil, fmt.Errorf("missing authentication browser proof")
	}
	state, err := randomKey()
	if err != nil {
		return nil, err
	}
	state = "oim_" + state
	payload, err := r.codec.seal("mfa", mfaPayload{p, idToken})
	if err != nil {
		return nil, err
	}
	err = r.options.Store.PutTransaction(ctx, Transaction{Key: digest(state), Kind: "pending_mfa", ProviderID: p.ID, UserID: uid, BrowserProof: digest(proof), ConfigDigest: p.Digest(), ExpiresAt: r.options.Now().Add(5 * time.Minute), Payload: payload})
	if err != nil {
		return nil, err
	}
	return &FinishResult{Challenge: state}, nil
}
func IsExternalChallenge(state string) bool { return strings.HasPrefix(state, "oim_") }
func (r *Runtime) CompleteMFA(ctx context.Context, state, proof, otp string) (*FinishResult, error) {
	if !IsExternalChallenge(state) || proof == "" {
		return nil, fmt.Errorf("invalid second factor challenge")
	}
	t, err := r.options.Store.Transaction(ctx, digest(state))
	if err != nil {
		return nil, err
	}
	if t.Kind != "pending_mfa" || t.UserID <= 0 || !t.ExpiresAt.After(r.options.Now()) || subtle.ConstantTimeCompare([]byte(t.BrowserProof), []byte(digest(proof))) != 1 {
		return nil, fmt.Errorf("second factor challenge or browser does not match")
	}
	registry, err := r.options.Registry(ctx)
	if err != nil {
		return nil, err
	}
	current, err := registry.Find(t.ProviderID)
	if err != nil || current.Digest() != t.ConfigDigest {
		return nil, fmt.Errorf("provider configuration changed; restart authentication")
	}
	if err = r.options.Store.ReserveAttempt(ctx, t, r.options.Now()); err != nil {
		return nil, err
	}
	if err = r.options.Native.ValidateOTP(ctx, t.UserID, otp); err != nil {
		return nil, err
	}
	var payload mfaPayload
	if err = r.codec.open("mfa", t.Payload, &payload); err != nil {
		return nil, err
	}
	if err = r.options.Store.Consume(ctx, t, r.options.Now()); err != nil {
		return nil, err
	}
	payload.Provider.Fingerprint = t.ConfigDigest
	return r.issueSession(ctx, t.UserID, payload.Provider, payload.IDToken)
}
