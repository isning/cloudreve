package controllers_test

import (
	"context"
	"encoding/json"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	ctl "github.com/cloudreve/Cloudreve/v4/routers/controllers"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	"github.com/cloudreve/Cloudreve/v4/service/basic"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOpenIDRegistryRejectsReusedIdentifiersAndPreservesOpaqueEntries(t *testing.T) {
	p := newTestIDP(t)
	r, d := newOpenIDFixture(t, p)
	r.PATCH("/api/v4/admin/settings", ctl.FromJSON[admin.SetSettingService](admin.SetSettingParamCtx{}), ctl.AdminSetSettings)
	r.GET("/api/v4/site/config/:section", ctl.FromUri[basic.GetSettingService](basic.GetSettingParamCtx{}), ctl.SiteConfig)
	registry, err := d.s.ExternalLoginProviders(context.Background())
	require.NoError(t, err)
	registry.NextID = 5
	registry.Providers[0].ID = 4
	raw, err := json.Marshal(registry)
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(raw, &document))
	document["future_wrapper"] = map[string]any{"preserve": true}
	document["providers"] = append(document["providers"].([]any), map[string]any{"id": 3, "type": "qq", "enabled": true, "config": map[string]any{"client_id": 42, "future": map[string]any{"value": "opaque"}}})
	raw, err = json.Marshal(document)
	require.NoError(t, err)
	// ID 3 already exists, and changing its type must be rejected.
	w := openIDRequest(t, r, "PATCH", "/api/v4/admin/settings", map[string]any{"settings": map[string]string{oidc.SettingName: string(raw)}}, nil)
	require.NotZero(t, responseCode(t, w))
	document["providers"].([]any)[1].(map[string]any)["id"] = 5
	document["next_id"] = 6
	raw, err = json.Marshal(document)
	require.NoError(t, err)
	w = openIDRequest(t, r, "PATCH", "/api/v4/admin/settings", map[string]any{"settings": map[string]string{oidc.SettingName: string(raw)}}, nil)
	require.Zero(t, responseCode(t, w), w.Body.String())
	stored, err := d.SettingClient().Get(context.Background(), oidc.SettingName)
	require.NoError(t, err)
	require.JSONEq(t, string(raw), stored)
	w = openIDRequest(t, r, "GET", "/api/v4/site/config/login", nil, nil)
	require.Zero(t, responseCode(t, w))
	require.NotContains(t, w.Body.String(), "qq")
	require.NotContains(t, w.Body.String(), "opaque")
	require.NotContains(t, w.Body.String(), "future_wrapper")
	document["next_id"] = 5
	raw, _ = json.Marshal(document)
	w = openIDRequest(t, r, "PATCH", "/api/v4/admin/settings", map[string]any{"settings": map[string]string{oidc.SettingName: string(raw)}}, nil)
	require.NotZero(t, responseCode(t, w))
}
func TestOpenIDConfiguredLegacyIdentifiersAreRealInstances(t *testing.T) {
	for _, id := range []int{0, 1, 2, 3, 10} {
		t.Run(string(rune('A'+id)), func(t *testing.T) {
			p := newTestIDP(t)
			r, d := newOpenIDFixture(t, p)
			changeProvider(t, d, func(reg *oidc.Registry) {
				reg.Providers[0].ID = id
				if id >= reg.NextID {
					reg.NextID = id + 1
				}
			})
			target, _ := prepareExternal(t, r, id, false, "")
			require.Contains(t, target, "callback%2Fopenid%2F")
		})
	}
	p := newTestIDP(t)
	r, _ := newOpenIDFixture(t, p)
	w := openIDRequest(t, r, "PUT", "/api/v4/session/openid", map[string]int{"provider": 2}, nil)
	require.NotZero(t, responseCode(t, w))
}
