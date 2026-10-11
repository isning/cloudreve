package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/tidwall/gjson"
	"golang.org/x/oauth2"
)

type protocolClient struct {
	digest   string
	verifier *coreoidc.IDTokenVerifier
}
type protocolClients struct {
	metadata map[int]providerMetadata
	mu       sync.Mutex
	clients  map[int]protocolClient
}
type verifiedProfile struct {
	Subject string
	IDToken string
	Claims  json.RawMessage
}

func (r *Runtime) verifier(p Provider) (*coreoidc.IDTokenVerifier, error) {
	r.protocols.mu.Lock()
	defer r.protocols.mu.Unlock()
	if r.protocols.clients == nil {
		r.protocols.clients = map[int]protocolClient{}
	}
	fingerprint := p.Digest()
	if c, ok := r.protocols.clients[p.ID]; ok && c.digest == fingerprint {
		return c.verifier, nil
	}
	algorithms := []string{}
	allowed := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
	for _, alg := range p.Wellknown.SigningAlgorithms {
		if slices.Contains(allowed, alg) {
			algorithms = append(algorithms, alg)
		}
	}
	if len(p.Wellknown.SigningAlgorithms) > 0 && len(algorithms) == 0 {
		return nil, fmt.Errorf("provider has no supported signature algorithm")
	}
	ctx := coreoidc.ClientContext(context.Background(), r.options.HTTP)
	v := coreoidc.NewVerifier(p.Wellknown.Issuer, coreoidc.NewRemoteKeySet(ctx, p.Wellknown.JWKSURI), &coreoidc.Config{ClientID: p.Config.ClientID, SupportedSigningAlgs: algorithms, Now: r.options.Now})
	r.protocols.clients[p.ID] = protocolClient{fingerprint, v}
	return v, nil
}
func (r *Runtime) exchange(ctx context.Context, p Provider, payload authPayload, code string) (*verifiedProfile, error) {
	config := oauth2.Config{ClientID: p.Config.ClientID, ClientSecret: p.Config.ClientSecret, RedirectURL: payload.Callback, Scopes: p.Scopes(), Endpoint: oauth2.Endpoint{AuthURL: p.Wellknown.AuthorizationEndpoint, TokenURL: p.Wellknown.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams}}
	ctx = coreoidc.ClientContext(ctx, r.options.HTTP)
	opts := []oauth2.AuthCodeOption{}
	if payload.Verifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", payload.Verifier))
	}
	token, err := config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("provider code exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("provider returned no ID token")
	}
	verifier, err := r.verifier(p)
	if err != nil {
		return nil, err
	}
	id, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("provider ID token validation failed")
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return nil, fmt.Errorf("provider access token hash validation failed")
	}
	if id.Subject == "" || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(payload.Nonce)) != 1 {
		return nil, fmt.Errorf("provider nonce or subject validation failed")
	}
	var claims json.RawMessage
	if err = id.Claims(&claims); err != nil {
		return nil, fmt.Errorf("invalid provider claims")
	}
	azp := gjson.GetBytes(claims, "azp").String()
	if len(id.Audience) > 1 && azp != p.Config.ClientID || azp != "" && azp != p.Config.ClientID {
		return nil, fmt.Errorf("provider authorized party validation failed")
	}
	merged := map[string]any{}
	if json.Unmarshal(claims, &merged) != nil {
		return nil, fmt.Errorf("invalid provider claims")
	}
	if p.Wellknown.UserinfoEndpoint != "" {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Wellknown.UserinfoEndpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("invalid userinfo endpoint")
		}
		request.Header.Set("Authorization", "Bearer "+token.AccessToken)
		response, err := r.options.HTTP.Do(request)
		if err != nil {
			return nil, fmt.Errorf("provider userinfo request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || response.StatusCode != 200 {
			return nil, fmt.Errorf("provider userinfo request failed")
		}
		var info map[string]any
		if json.Unmarshal(body, &info) != nil || info["sub"] != id.Subject {
			return nil, fmt.Errorf("provider userinfo subject validation failed")
		}
		for key, value := range info {
			merged[key] = value
		}
	}
	claims, err = json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("invalid provider claims")
	}
	subMapping := p.Config.SubMapping
	if subMapping == "" {
		subMapping = "sub"
	}
	if gjson.GetBytes(claims, subMapping).String() != id.Subject {
		return nil, fmt.Errorf("mapped subject must equal verified ID token subject")
	}
	return &verifiedProfile{Subject: id.Subject, IDToken: raw, Claims: claims}, nil
}
