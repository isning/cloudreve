package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
)

type FinishRequest struct {
	ProviderID          int    `json:"provider_id"`
	Code                string `json:"code"`
	SessionID           string `json:"session_id"`
	Proof               string `json:"-"`
	AuthenticatedUserID int    `json:"-"`
}
type FinishResult struct {
	Token     *Token
	Linked    bool
	UserID    int
	Challenge string
}

func (r *Runtime) Finish(ctx context.Context, request FinishRequest) (*FinishResult, error) {
	if request.Code == "" || request.SessionID == "" || request.Proof == "" {
		return nil, fmt.Errorf("missing code, state or browser proof")
	}
	t, err := r.options.Store.Transaction(ctx, digest(request.SessionID))
	if err != nil {
		return nil, err
	}
	proof := digest(request.Proof)
	if subtle.ConstantTimeCompare([]byte(t.BrowserProof), []byte(proof)) != 1 {
		return nil, fmt.Errorf("authentication browser proof does not match")
	}
	if t.Kind != "auth" || t.ProviderID != request.ProviderID || !t.ExpiresAt.After(r.options.Now()) {
		return nil, fmt.Errorf("authentication transaction expired or provider does not match")
	}
	registry, err := r.options.Registry(ctx)
	if err != nil {
		return nil, err
	}
	p, err := registry.Find(t.ProviderID)
	if err != nil {
		return nil, err
	}
	if t.ConfigDigest != p.Digest() {
		return nil, fmt.Errorf("provider configuration changed; restart authentication")
	}
	var payload authPayload
	if err = r.codec.open("auth", t.Payload, &payload); err != nil {
		return nil, err
	}
	if payload.Linking && (t.UserID <= 0 || request.AuthenticatedUserID > 0 && request.AuthenticatedUserID != t.UserID) {
		return nil, fmt.Errorf("association account does not match prepared transaction")
	}
	if err = r.options.Store.Consume(ctx, t, r.options.Now()); err != nil {
		return nil, err
	}
	// Use fixed, encrypted metadata prepared under the current configuration.
	payload.Provider.Fingerprint = t.ConfigDigest
	p = payload.Provider
	// No database transaction remains open during the external exchange.
	profile, err := r.exchange(ctx, p, payload, request.Code)
	if err != nil {
		return nil, err
	}
	uid, err := r.options.Store.ResolveIdentity(ctx, Identity{ProviderID: p.ID, Issuer: p.Wellknown.Issuer, Subject: profile.Subject}, t.UserID)
	if errors.Is(err, ErrUnassociated) && !payload.Linking && p.Config.DirectSignIn {
		group := 2
		if r.options.DefaultGroup != nil {
			group = r.options.DefaultGroup(ctx)
		}
		mapped, mapErr := mappedProfile(p, profile, group)
		if mapErr != nil {
			return nil, mapErr
		}
		uid, err = r.options.Store.CreateIdentityAccount(ctx, Identity{ProviderID: p.ID, Issuer: p.Wellknown.Issuer, Subject: profile.Subject}, mapped)
	}

	if err != nil {
		return nil, err
	}
	if payload.Linking {
		return &FinishResult{Linked: true, UserID: uid}, nil
	}
	return r.signSession(WithBrowserProof(ctx, request.Proof), uid, p, profile.IDToken)
}

var ErrUnassociated = errors.New("sign in locally and associate this external identity first")
