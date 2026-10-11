package dependency

import (
	"context"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"net/http"
)

func (d *dependency) OIDC() *oidc.Runtime {
	if d.oidcRuntime != nil {
		return d.oidcRuntime
	}
	settings := d.SettingProvider()
	d.oidcRuntime = oidc.New(oidc.Options{Registry: settings.ExternalLoginProviders, DefaultGroup: settings.DefaultGroup, Native: auth.NewOIDCSessionBridge(d.TokenAuth(), d.UserClient(), d.HashIDEncoder(), d.KV(), settings), Store: inventory.NewExternalAuthStore(d.DBClient()), Key: []byte(settings.SecretKey(context.Background())), HTTP: &http.Client{Transport: http.DefaultTransport}, SiteURL: func(ctx context.Context) string { return settings.SiteURL(ctx).String() }})
	return d.oidcRuntime
}
