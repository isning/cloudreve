package oidc

import (
	"context"
	"fmt"
	"net/url"
)

type logoutPayload struct{ Endpoint, IDToken, ReturnURI, ConfigDigest string }

func (r *Runtime) signSession(ctx context.Context, uid int, p Provider, idToken string) (*FinishResult, error) {
	if r.options.Native == nil {
		return nil, fmt.Errorf("native session service is unavailable")
	}
	mfa, err := r.options.Native.RequiresMFA(ctx, uid)
	if err != nil {
		return nil, err
	}
	if mfa {
		return r.prepareMFA(ctx, uid, p, idToken)
	}
	return r.issueSession(ctx, uid, p, idToken)
}
func (r *Runtime) issueSession(ctx context.Context, uid int, p Provider, idToken string) (*FinishResult, error) {
	token, err := r.options.Native.Issue(ctx, uid, "openid")
	if err != nil {
		return nil, err
	}
	material, err := r.codec.seal("logout", logoutPayload{Endpoint: p.Wellknown.EndSessionEndpoint, IDToken: idToken, ReturnURI: r.options.SiteURL(ctx), ConfigDigest: p.Digest()})
	if err != nil {
		return nil, err
	}
	if err = r.options.Store.CreateSession(ctx, Session{RootID: token.RootID, UserID: uid, ProviderID: p.ID, Issuer: p.Wellknown.Issuer, ExpiresAt: token.RefreshExpires, Payload: material}); err != nil {
		return nil, fmt.Errorf("cannot persist external root session")
	}
	return &FinishResult{UserID: uid, Token: token}, nil
}
func (r *Runtime) Refresh(ctx context.Context, raw string) (*Token, error) {
	claims, err := r.options.Native.Claims(ctx, raw)
	if err != nil || !claims.Refresh || claims.RootID == "" {
		return nil, fmt.Errorf("invalid refresh token")
	}
	if claims.Source == "" {
		return r.options.Native.Refresh(ctx, raw)
	}
	if claims.Source != "openid" {
		return nil, fmt.Errorf("unknown session source")
	}
	session, err := r.options.Store.Session(ctx, claims.RootID)
	if err != nil || session.UserID != claims.UserID || session.Revoked || !session.ExpiresAt.After(r.options.Now()) || session.ExpiresAt.Before(claims.ExpiresAt) {
		return nil, fmt.Errorf("external session is expired or revoked")
	}
	var material logoutPayload
	if session.ProviderID < 0 || !validEndpoint(session.Issuer) || r.codec.open("logout", session.Payload, &material) != nil || material.ConfigDigest == "" {
		return nil, fmt.Errorf("external session is corrupt")
	}
	token, err := r.options.Native.Refresh(ctx, raw)
	if err != nil {
		return nil, err
	}
	if token.RootID != session.RootID || token.UserID != session.UserID {
		return nil, fmt.Errorf("native root session changed")
	}
	if err = r.options.Store.TouchSession(ctx, session, token.RefreshExpires, r.options.Now()); err != nil {
		return nil, err
	}
	return token, nil
}
func (r *Runtime) Logout(ctx context.Context, raw string) (string, error) {
	claims, err := r.options.Native.Claims(ctx, raw)
	if err != nil || !claims.Refresh || claims.RootID == "" {
		return "", fmt.Errorf("invalid refresh token")
	}
	if claims.Source == "" {
		return "", r.options.Native.Logout(ctx, raw)
	}
	if claims.Source != "openid" {
		return "", fmt.Errorf("unknown session source")
	}
	session, err := r.options.Store.Session(ctx, claims.RootID)
	if err != nil || session.UserID != claims.UserID {
		return "", fmt.Errorf("invalid external session")
	}
	if err = r.options.Store.RevokeSession(ctx, session, r.options.Now()); err != nil {
		return "", err
	}

	if session.Revoked || len(session.Payload) == 0 {
		return "", nil
	}
	var material logoutPayload
	if r.codec.open("logout", session.Payload, &material) != nil || material.Endpoint == "" || !validEndpoint(material.Endpoint) || !validEndpoint(material.ReturnURI) {
		return "", nil
	}
	target, err := url.Parse(material.Endpoint)
	if err != nil {
		return "", nil
	}
	query := target.Query()
	query.Set("id_token_hint", material.IDToken)
	query.Set("post_logout_redirect_uri", material.ReturnURI)
	target.RawQuery = query.Encode()
	return target.String(), nil
}
