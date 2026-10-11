package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Runtime struct {
	protocols protocolClients
	options   Options
	codec     *payloadCodec
}

func New(options Options) *Runtime {
	if options.Now == nil {
		options.Now = time.Now
	}
	options.HTTP = providerHTTP(options.HTTP)
	return &Runtime{options: options, codec: newPayloadCodec(options.Key)}
}
func (r *Runtime) Prepare(ctx context.Context, request PrepareRequest) (*Authorization, error) {
	registry, err := r.options.Registry(ctx)
	if err != nil {
		return nil, err
	}
	p, err := registry.Find(request.Provider)
	if err != nil {
		return nil, err
	}
	if len(request.Hint) > 1024 {
		return nil, fmt.Errorf("login hint is too long")
	}
	if request.Linking && request.UserID <= 0 {
		return nil, fmt.Errorf("sign in locally before associating an identity")
	}
	p, err = r.normalizeProvider(ctx, p)
	if err != nil {
		return nil, err
	}
	state, err := randomKey()
	if err != nil {
		return nil, err
	}
	proof, err := randomKey()
	if err != nil {
		return nil, err
	}
	nonce, err := randomKey()
	if err != nil {
		return nil, err
	}
	callback, err := r.CallbackURL(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	payload := authPayload{Nonce: nonce, Callback: callback, Linking: request.Linking, Provider: p}
	u, err := url.Parse(p.Wellknown.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization endpoint")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.Config.ClientID)
	q.Set("redirect_uri", callback)
	q.Set("scope", strings.Join(p.Scopes(), " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	if p.Type == "logto" {
		if p.Config.DirectSSO != "" {
			q.Set("direct_sign_in", p.Config.DirectSSO)
		}
		if request.Hint != "" {
			q.Set("login_hint", request.Hint)
		}
	}

	if slices.Contains(p.Wellknown.PKCEMethods, "S256") {
		payload.Verifier, err = randomKey()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(payload.Verifier))
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		q.Set("code_challenge_method", "S256")
	}
	material, err := r.codec.seal("auth", payload)
	if err != nil {
		return nil, err
	}
	uid := 0
	if request.Linking {
		uid = request.UserID
	}
	err = r.options.Store.PutTransaction(ctx, Transaction{Key: digest(state), Kind: "auth", ProviderID: p.ID, UserID: uid, BrowserProof: digest(proof), ConfigDigest: p.Digest(), ExpiresAt: r.options.Now().Add(10 * time.Minute), Payload: material})
	if err != nil {
		return nil, fmt.Errorf("cannot prepare authentication transaction")
	}
	u.RawQuery = q.Encode()
	return &Authorization{URL: u.String(), State: state, Proof: proof}, nil
}

// CallbackURL exposes the same effective callback used during authorization,
// including configuration overrides and request-specific site selection.
func (r *Runtime) CallbackURL(ctx context.Context, provider int) (string, error) {
	if provider < 0 {
		return "", fmt.Errorf("invalid provider identifier")
	}
	callback := strings.TrimRight(r.options.SiteURL(ctx), "/") + "/callback/openid/" + strconv.Itoa(provider)
	if !validEndpoint(callback) {
		return "", fmt.Errorf("invalid configured site URL")
	}
	return callback, nil
}

// Cleanup is invoked by the existing application scheduler, never per callback.
func (r *Runtime) Cleanup(ctx context.Context) error {
	if err := r.options.Store.Cleanup(ctx, r.options.Now()); err != nil {
		return err
	}
	registry, err := r.options.Registry(ctx)
	if err != nil {
		return err
	}
	valid := map[int]string{}
	for _, p := range registry.Providers {
		if p.Enabled && p.Supported() {
			valid[p.ID] = p.Digest()
		}
	}
	r.protocols.mu.Lock()
	defer r.protocols.mu.Unlock()
	for id, client := range r.protocols.clients {
		if valid[id] != client.digest {
			delete(r.protocols.clients, id)
		}
	}
	for id, metadata := range r.protocols.metadata {
		if valid[id] != metadata.digest {
			delete(r.protocols.metadata, id)
		}
	}
	return nil
}
