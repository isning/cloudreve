package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"os"
	"sync"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
)

const ExternalAuthSchemaVersion = "oidc_extension_schema_v1"

var externalSchemaMutex sync.Mutex

// EnsureExternalAuthSchema is additive and independent of the official version.
// File locks (SQLite) or database advisory locks coordinate production processes.
func EnsureExternalAuthSchema(ctx context.Context, client *ent.Client) error {
	externalSchemaMutex.Lock()
	defer externalSchemaMutex.Unlock()
	ctx = context.WithValue(ctx, debug.SkipDbLogging{}, true)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	unlock, err := externalMigrationLock(ctx, client)
	if err != nil {
		return err
	}
	defer unlock()
	exists, err := client.Setting.Query().Where(setting.Name(ExternalAuthSchemaVersion), setting.Value("complete")).Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := entmigrate.Create(ctx, client.Schema, []*schema.Table{
		entmigrate.UsersTable, entmigrate.ExternalIdentitiesTable, entmigrate.OpenIDTransactionsTable, entmigrate.OpenIDSessionsTable,
	}, schema.WithAtlas(false)); err != nil {
		return fmt.Errorf("initialize external authentication schema: %w", err)
	}
	initial := oidc.EmptyConfig
	if override, ok := os.LookupEnv(EnvDefaultOverwritePrefix + oidc.SettingName); ok {
		if _, err := oidc.ParseRegistry(override); err != nil {
			return fmt.Errorf("invalid external provider default override")
		}
		initial = override
	}
	if err := client.Setting.Create().SetName(oidc.SettingName).
		SetValue(initial).
		OnConflictColumns(setting.FieldName).DoNothing().Exec(ctx); err != nil {
		// Ent's RETURNING path reports ErrNoRows for a successful DO NOTHING.
		// Preserve the already-installed configuration and verify it really exists.
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		present, queryErr := client.Setting.Query().Where(setting.Name(oidc.SettingName)).Exist(ctx)
		if queryErr != nil || !present {
			return fmt.Errorf("provider configuration bootstrap is incomplete")
		}
	}
	return client.Setting.Create().SetName(ExternalAuthSchemaVersion).SetValue("complete").
		OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx)
}
