package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (r *Runtime) Discovery(ctx context.Context, endpoint string) (string, error) {
	if !validEndpoint(endpoint) {
		return "", fmt.Errorf("invalid discovery URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("invalid discovery URL")
	}
	response, err := r.options.HTTP.Do(request)
	if err != nil {
		return "", fmt.Errorf("discovery request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || response.StatusCode != 200 || len(data) > 1<<20 {
		return "", fmt.Errorf("discovery response is unavailable or too large")
	}
	var metadata Metadata
	if json.Unmarshal(data, &metadata) != nil {
		return "", fmt.Errorf("invalid discovery document")
	}
	if err = metadata.Validate(); err != nil {
		return "", err
	}
	return string(data), nil
}
func (r *Runtime) normalizeProvider(ctx context.Context, p Provider) (Provider, error) {
	if p.Type != "logto" {
		return p, nil
	}
	fingerprint := p.Digest()
	r.protocols.mu.Lock()
	if cached, ok := r.protocols.metadata[p.ID]; ok && cached.digest == fingerprint {
		p.Fingerprint = fingerprint
		p.Config.ClientID = p.Config.AppID
		p.Config.ClientSecret = p.Config.AppSecret
		p.Wellknown = cached.metadata
		r.protocols.mu.Unlock()
		return p, nil
	}
	r.protocols.mu.Unlock()
	endpoint := strings.TrimRight(p.Config.Endpoint, "/")
	issuer := endpoint + "/oidc"
	if strings.HasSuffix(endpoint, "/oidc") {
		issuer = endpoint
	}
	raw, err := r.Discovery(ctx, issuer+"/.well-known/openid-configuration")
	if err != nil {
		return Provider{}, err
	}
	var metadata Metadata
	if json.Unmarshal([]byte(raw), &metadata) != nil || metadata.Issuer != issuer {
		return Provider{}, fmt.Errorf("Logto discovery issuer does not match configured endpoint")
	}
	p.Fingerprint = fingerprint
	p.Config.ClientID = p.Config.AppID
	p.Config.ClientSecret = p.Config.AppSecret
	p.Wellknown = metadata
	r.protocols.mu.Lock()
	if r.protocols.metadata == nil {
		r.protocols.metadata = map[int]providerMetadata{}
	}
	r.protocols.metadata[p.ID] = providerMetadata{fingerprint, metadata}
	r.protocols.mu.Unlock()
	return p, nil
}

type providerMetadata struct {
	digest   string
	metadata Metadata
}
