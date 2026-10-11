// Package oidc implements external authentication without depending on the
// application's database, native authentication, settings or HTTP framework.
package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const SettingName = "external_login_providers"
const EmptyConfig = `{"version":1,"next_id":3,"providers":[]}`

type Registry struct {
	Version   int        `json:"version"`
	NextID    int        `json:"next_id"`
	Providers []Provider `json:"providers"`
}

type Provider struct {
	Fingerprint string   `json:"-"`
	ID          int      `json:"id"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	Config      Config   `json:"config"`
	Wellknown   Metadata `json:"wellknown"`
}

type Config struct {
	ClientID          string         `json:"client_id"`
	ClientSecret      string         `json:"client_secret"`
	Scope             string         `json:"scope"`
	DisplayName       string         `json:"display_name"`
	Icon              string         `json:"icon"`
	DirectSignIn      bool           `json:"direct_sign_in"`
	SubMapping        string         `json:"sub_field_mapping"`
	EmailMapping      string         `json:"email_field_mapping"`
	AvatarMapping     string         `json:"avatar_field_mapping"`
	NameMapping       string         `json:"name_field_mapping"`
	GroupMappingField string         `json:"group_field_mapping"`
	GroupMapping      map[string]int `json:"group_mapping"`
	Endpoint          string         `json:"endpoint"`
	AppID             string         `json:"app_id"`
	AppSecret         string         `json:"app_secret"`
	DirectSSO         string         `json:"direct_sso"`
}

type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported"`
	PKCEMethods           []string `json:"code_challenge_methods_supported"`
}

type PublicProvider struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Icon    string `json:"icon"`
	Enabled bool   `json:"enabled"`
}

func ParseRegistry(raw string) (*Registry, error) {
	var r Registry
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("invalid external provider configuration")
	}
	if r.Version != 1 || r.NextID < 3 || r.Providers == nil {
		return nil, fmt.Errorf("unsupported external provider configuration")
	}
	seen := map[int]bool{}
	for _, p := range r.Providers {
		if p.ID < 0 || seen[p.ID] || p.ID >= r.NextID || p.Type == "" {
			return nil, fmt.Errorf("invalid or duplicate provider identifier")
		}
		seen[p.ID] = true
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("provider %d: %w", p.ID, err)
		}
	}
	return &r, nil
}

func (p Provider) Supported() bool { return p.Type == "oidc" || p.Type == "logto" }
func (p Provider) Validate() error {
	if !p.Supported() || !p.Enabled {
		return nil
	}
	c := p.Config
	if p.Type == "logto" {
		if c.AppID == "" || c.AppSecret == "" {
			return fmt.Errorf("Logto application ID and secret are required")
		}
		if !validEndpoint(c.Endpoint) {
			return fmt.Errorf("invalid Logto endpoint")
		}
	} else {
		if c.ClientID == "" || c.ClientSecret == "" {
			return fmt.Errorf("OIDC client ID and secret are required")
		}
		if err := p.Wellknown.Validate(); err != nil {
			return err
		}
	}
	if len(c.DisplayName) > 100 || len(c.Scope) > 2048 {
		return fmt.Errorf("provider name or scope is too long")
	}
	for _, scope := range strings.Split(c.Scope, ",") {
		for _, ch := range strings.TrimSpace(scope) {
			if ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\' {
				return fmt.Errorf("invalid additional scope")
			}
		}
	}
	for _, mapping := range []string{c.SubMapping, c.EmailMapping, c.NameMapping, c.AvatarMapping, c.GroupMappingField} {
		if len(mapping) > 1024 {
			return fmt.Errorf("claim mapping is too long")
		}
	}
	for _, group := range c.GroupMapping {
		if group <= 0 {
			return fmt.Errorf("invalid target group")
		}
	}
	return nil
}

func (m Metadata) Validate() error {
	for _, endpoint := range []string{m.Issuer, m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if !validEndpoint(endpoint) {
			return fmt.Errorf("issuer, authorization, token and JWKS endpoints must be absolute HTTP(S) URLs")
		}
	}
	for _, endpoint := range []string{m.UserinfoEndpoint, m.EndSessionEndpoint} {
		if endpoint != "" && !validEndpoint(endpoint) {
			return fmt.Errorf("invalid optional provider endpoint")
		}
	}
	return nil
}
func validEndpoint(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.Fragment == ""
}
func (r Registry) Find(id int) (Provider, error) {
	for _, p := range r.Providers {
		if p.ID == id && p.Enabled && p.Supported() {
			return p, nil
		}
	}
	return Provider{}, fmt.Errorf("provider is unavailable")
}
func (r Registry) Public() []PublicProvider {
	result := []PublicProvider{}
	for _, p := range r.Providers {
		if !p.Enabled || !p.Supported() {
			continue
		}
		name := p.Config.DisplayName
		if name == "" {
			name = strings.ToUpper(p.Type)
		}
		result = append(result, PublicProvider{p.ID, p.Type, name, p.Config.Icon, true})
	}
	return result
}
func (p Provider) Digest() string {
	if p.Fingerprint != "" {
		return p.Fingerprint
	}
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func (p Provider) Scopes() []string {
	result := []string{"openid", "email", "profile"}
	seen := map[string]bool{"openid": true, "email": true, "profile": true}
	for _, scope := range strings.Split(p.Config.Scope, ",") {
		scope = strings.TrimSpace(scope)
		if scope != "" && !seen[scope] {
			result = append(result, scope)
			seen[scope] = true
		}
	}
	return result
}

// UnmarshalJSON accepts opaque unsupported provider configurations. Their raw
// representation is preserved by the settings editor and database save path.
func (p *Provider) UnmarshalJSON(data []byte) error {
	var envelope struct {
		ID        int             `json:"id"`
		Type      string          `json:"type"`
		Enabled   bool            `json:"enabled"`
		Config    json.RawMessage `json:"config"`
		Wellknown json.RawMessage `json:"wellknown"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	p.ID, p.Type, p.Enabled = envelope.ID, envelope.Type, envelope.Enabled
	if !p.Supported() {
		return nil
	}
	if err := json.Unmarshal(envelope.Config, &p.Config); err != nil {
		return err
	}
	if len(envelope.Wellknown) > 0 {
		return json.Unmarshal(envelope.Wellknown, &p.Wellknown)
	}
	return nil
}
func (r Registry) ValidateUpdate(previous Registry) error {
	if r.NextID < previous.NextID {
		return fmt.Errorf("next_id must never decrease")
	}
	existing := map[int]string{}
	for _, p := range previous.Providers {
		existing[p.ID] = p.Type
	}
	for _, p := range r.Providers {
		if kind, ok := existing[p.ID]; ok {
			if kind != p.Type {
				return fmt.Errorf("provider type cannot change under an existing identifier")
			}
		} else if p.ID < previous.NextID || p.ID < 3 {
			return fmt.Errorf("new providers must use unused monotonic identifiers starting at 3")
		}
	}
	return nil
}

// Issuer is the permanent identity namespace, including Logto's OIDC suffix.
func (p Provider) Issuer() string {
	if p.Type != "logto" {
		return p.Wellknown.Issuer
	}
	endpoint := strings.TrimRight(p.Config.Endpoint, "/")
	if strings.HasSuffix(endpoint, "/oidc") {
		return endpoint
	}
	return endpoint + "/oidc"
}
