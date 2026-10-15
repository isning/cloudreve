package inventory

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
)

const AuditSchemaVersion = "audit_extension_schema_v1"

// EnsureAuditSchema also runs for already initialized upstream databases.
func EnsureAuditSchema(ctx context.Context, client *ent.Client) error {
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
	exists, err := client.Setting.Query().Where(setting.Name(AuditSchemaVersion), setting.Value("complete")).Exist(ctx)
	if err != nil || exists {
		return err
	}
	if err := entmigrate.Create(ctx, client.Schema, []*schema.Table{entmigrate.AuditLogsTable, entmigrate.AuditArchivesTable, entmigrate.AuditArchiveItemsTable}, schema.WithAtlas(false)); err != nil {
		return fmt.Errorf("initialize audit extension schema: %w", err)
	}
	for _, key := range []string{"audit_enabled_flags", "audit_record_ip"} {
		if err := client.Setting.Create().SetName(key).SetValue(DefaultSettings[key]).OnConflictColumns(setting.FieldName).UpdateName().Exec(ctx); err != nil {
			return err
		}
	}
	return client.Setting.Create().SetName(AuditSchemaVersion).SetValue("complete").OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx)
}
