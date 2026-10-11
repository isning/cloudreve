package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type Transaction struct {
	Key, Kind                  string
	ProviderID, UserID         int
	BrowserProof, ConfigDigest string
	ExpiresAt                  time.Time
	Payload                    []byte
}

type Identity struct {
	ProviderID      int
	Issuer, Subject string
}

func (id Identity) Key() string {
	data, _ := json.Marshal([]any{id.ProviderID, id.Issuer, id.Subject})
	return digest(string(data))
}

type Token struct {
	AccessToken    string    `json:"access_token"`
	RefreshToken   string    `json:"refresh_token"`
	AccessExpires  time.Time `json:"access_expires"`
	RefreshExpires time.Time `json:"refresh_expires"`
	UserID         int       `json:"-"`
	RootID         string    `json:"-"`
}
type SessionClaims struct {
	UserID         int
	RootID, Source string
	ExpiresAt      time.Time
	Refresh        bool
}
type Native interface {
	RequiresMFA(context.Context, int) (bool, error)
	ValidateOTP(context.Context, int, string) error
	Issue(context.Context, int, string) (*Token, error)
	Refresh(context.Context, string) (*Token, error)
	Claims(context.Context, string) (SessionClaims, error)
	Logout(context.Context, string) error
}
type Session struct {
	RootID             string
	UserID, ProviderID int
	Issuer             string
	ExpiresAt          time.Time
	Revoked            bool
	Payload            []byte
}

type Store interface {
	CreateIdentityAccount(context.Context, Identity, Profile) (int, error)
	Cleanup(context.Context, time.Time) error
	Bindings(context.Context, int) ([]Binding, error)
	UnlinkIdentity(context.Context, int, int, map[string]bool) error
	CreateSession(context.Context, Session) error
	Session(context.Context, string) (Session, error)
	TouchSession(context.Context, Session, time.Time, time.Time) error
	RevokeSession(context.Context, Session, time.Time) error

	ResolveIdentity(context.Context, Identity, int) (int, error)
	PutTransaction(context.Context, Transaction) error
	Transaction(context.Context, string) (Transaction, error)
	Consume(context.Context, Transaction, time.Time) error
	ReserveAttempt(context.Context, Transaction, time.Time) error
}

type Options struct {
	DefaultGroup func(context.Context) int
	Native       Native
	Registry     func(context.Context) (*Registry, error)
	Store        Store
	Key          []byte
	HTTP         *http.Client
	SiteURL      func(context.Context) string
	Now          func() time.Time
}

type PrepareRequest struct {
	Provider int    `json:"provider"`
	Hint     string `json:"hint"`
	Linking  bool   `json:"linking"`
	UserID   int    `json:"-"`
}
type Authorization struct{ URL, State, Proof string }
type authPayload struct {
	Provider                  Provider
	Nonce, Verifier, Callback string
	Linking                   bool
}
