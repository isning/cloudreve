package inventory

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/node"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
)

const StorageSchemaVersion = "storage_extension_schema_v4"

// EnsureStorageSchema extends existing installations independently of the
// upstream version marker. It shares the existing extension DDL lock so storage
// and authentication initializers cannot race in production.
func EnsureStorageSchema(ctx context.Context, client *ent.Client) error {
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
	exists, err := client.Setting.Query().Where(setting.Name(StorageSchemaVersion), setting.Value("complete")).Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := entmigrate.Create(ctx, client.Schema, []*schema.Table{entmigrate.GroupPoliciesTable, entmigrate.RelocationItemsTable, entmigrate.RelocationAttemptsTable}, schema.WithAtlas(false)); err != nil {
		return fmt.Errorf("initialize storage extension schema: %w", err)
	}
	nodes, err := client.Node.Query().All(ctx)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		capabilities := boolset.BooleanSet{}
		if n.Capabilities != nil {
			capabilities = append(capabilities, (*n.Capabilities)...)
		}
		supported := n.Type == node.TypeMaster
		if capabilities.Enabled(int(types.NodeCapabilityRelocate)) == supported {
			continue
		}
		boolset.Set(types.NodeCapabilityRelocate, supported, &capabilities)
		if err := client.Node.UpdateOne(n).SetCapabilities(&capabilities).Exec(ctx); err != nil {
			return err
		}
	}
	return client.Setting.Create().SetName(StorageSchemaVersion).SetValue("complete").OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx)
}
