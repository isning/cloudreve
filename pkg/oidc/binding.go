package oidc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Binding struct {
	Provider int       `json:"provider"`
	LinkedAt time.Time `json:"linked_at"`
	Issuer   string    `json:"-"`
}

func (r *Runtime) View(ctx context.Context, uid int) ([]Binding, error) {
	if uid <= 0 {
		return nil, fmt.Errorf("sign in first")
	}
	return r.options.Store.Bindings(ctx, uid)
}
func (r *Runtime) Unlink(ctx context.Context, uid, provider int) error {
	if uid <= 0 {
		return fmt.Errorf("sign in first")
	}
	registry, err := r.options.Registry(ctx)
	if err != nil {
		return err
	}
	usable := map[string]bool{}
	for _, p := range registry.Providers {
		if p.Supported() && p.Enabled {
			issuer := p.Wellknown.Issuer
			if p.Type == "logto" {
				issuer = strings.TrimRight(p.Config.Endpoint, "/")
				if !strings.HasSuffix(issuer, "/oidc") {
					issuer += "/oidc"
				}
			}
			usable[strconv.Itoa(p.ID)+":"+issuer] = true
		}
	}
	return r.options.Store.UnlinkIdentity(ctx, uid, provider, usable)
}
