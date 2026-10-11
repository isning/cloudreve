package auth

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/pquerna/otp/totp"
)

type oidcSessionBridge struct {
	tokens   TokenAuth
	users    inventory.UserClient
	encoder  hashid.Encoder
	kv       cache.Driver
	settings setting.Provider
}

func NewOIDCSessionBridge(tokens TokenAuth, users inventory.UserClient, encoder hashid.Encoder, kv cache.Driver, settings setting.Provider) oidc.Native {
	return &oidcSessionBridge{tokens, users, encoder, kv, settings}
}
func (b *oidcSessionBridge) RequiresMFA(ctx context.Context, uid int) (bool, error) {
	u, err := b.users.GetActiveByID(ctx, uid)
	if err != nil {
		return false, fmt.Errorf("account is unavailable")
	}
	return u.TwoFactorSecret != "", nil
}
func (b *oidcSessionBridge) Issue(ctx context.Context, uid int, source string) (*oidc.Token, error) {
	u, err := b.users.GetActiveByID(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("account is unavailable")
	}
	token, err := b.tokens.Issue(ctx, &IssueTokenArgs{User: u, SessionSource: source})
	if err != nil {
		return nil, fmt.Errorf("cannot sign native session")
	}
	return b.convert(ctx, token)
}
func (b *oidcSessionBridge) convert(ctx context.Context, t *Token) (*oidc.Token, error) {
	claims, err := b.tokens.Claims(ctx, t.RefreshToken)
	if err != nil || claims.RootTokenID == nil {
		return nil, fmt.Errorf("invalid native root session")
	}
	uid, err := b.encoder.Decode(claims.Subject, hashid.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid native account")
	}
	expires := t.RefreshExpires
	if claims.SessionSource == "openid" {
		expires = claims.ExpiresAt.Time
	}
	return &oidc.Token{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, AccessExpires: t.AccessExpires, RefreshExpires: expires, RootID: claims.RootTokenID.String(), UserID: uid}, nil
}
func (b *oidcSessionBridge) Refresh(ctx context.Context, raw string) (*oidc.Token, error) {
	t, err := b.tokens.Refresh(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}
	return b.convert(ctx, t)
}
func (b *oidcSessionBridge) Claims(ctx context.Context, raw string) (oidc.SessionClaims, error) {
	c, err := b.tokens.Claims(ctx, raw)
	if err != nil {
		return oidc.SessionClaims{}, fmt.Errorf("invalid native token")
	}
	uid, err := b.encoder.Decode(c.Subject, hashid.UserID)
	if err != nil || c.ExpiresAt == nil {
		return oidc.SessionClaims{}, fmt.Errorf("invalid native token")
	}
	root := ""
	if c.RootTokenID != nil {
		root = c.RootTokenID.String()
	}
	return oidc.SessionClaims{UserID: uid, RootID: root, Source: c.SessionSource, ExpiresAt: c.ExpiresAt.Time, Refresh: c.TokenType == TokenTypeRefresh}, nil
}
func (b *oidcSessionBridge) Logout(ctx context.Context, raw string) error {
	c, err := b.Claims(ctx, raw)
	if err != nil || !c.Refresh || c.RootID == "" {
		return fmt.Errorf("invalid refresh token")
	}
	ttl := int(b.settings.TokenAuth(ctx).RefreshTokenTTL.Seconds()) + 10
	if ttl <= 0 {
		return fmt.Errorf("expired refresh token")
	}
	return b.kv.Set(RevokeTokenPrefix+c.RootID, true, ttl)
}

func (b *oidcSessionBridge) ValidateOTP(ctx context.Context, uid int, code string) error {
	u, err := b.users.GetActiveByID(ctx, uid)
	if err != nil || u.TwoFactorSecret == "" {
		return fmt.Errorf("second factor account is unavailable")
	}
	if !totp.Validate(code, u.TwoFactorSecret) {
		return fmt.Errorf("incorrect second factor code")
	}
	return nil
}
