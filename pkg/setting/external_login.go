package setting

import (
	"context"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
)

func (s *settingProvider) ExternalLoginProviders(ctx context.Context) (*oidc.Registry, error) {
	return oidc.ParseRegistry(s.getString(ctx, oidc.SettingName, oidc.EmptyConfig))
}
