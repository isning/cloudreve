package inventory

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/node"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
)

const StorageSchemaVersion = "storage_extension_schema_v10"

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
	if err := entmigrate.Create(ctx, client.Schema, []*schema.Table{entmigrate.GroupPoliciesTable, entmigrate.PolicyLoadBalancesTable, entmigrate.RelocationItemsTable, entmigrate.RelocationAttemptsTable, entmigrate.RelocationPlansTable, entmigrate.StorageObjectsTable, entmigrate.StorageObjectReadersTable}, schema.WithAtlas(false)); err != nil {
		return fmt.Errorf("initialize storage extension schema: %w", err)
	}
	tx, err := client.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client = tx.Client()
	if err := migrateGroupPolicies(ctx, client); err != nil {
		return fmt.Errorf("migrate group storage policies: %w", err)
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
	if err := client.Setting.Create().SetName(StorageSchemaVersion).SetValue("complete").OnConflictColumns(setting.FieldName).UpdateNewValues().Exec(ctx); err != nil {
		return err
	}
	return tx.Commit()
}

// Upgrade legacy defaults once. Existing ordered grants are authoritative and
// must not be replaced or supplemented by an obsolete default column.
func migrateGroupPolicies(ctx context.Context, client *ent.Client) error {
	// Older group deletion retained extension grants. Match the native group
	// lifecycle before treating every remaining grant as a deletion dependency.
	if _, err := client.GroupPolicy.Delete().Where(grouppolicy.HasGroupWith(group.DeletedAtNotNil())).Exec(ctx); err != nil {
		return err
	}
	groups, err := client.Group.Query().WithStoragePolicies().WithPolicyAssignments(func(q *ent.GroupPolicyQuery) {
		q.Order(ent.Asc(grouppolicy.FieldPosition))
	}).All(ctx)
	if err != nil {
		return err
	}
	for _, group := range groups {
		defaultID := 0
		if len(group.Edges.PolicyAssignments) > 0 {
			defaultID = group.Edges.PolicyAssignments[0].StoragePolicyID
		} else if group.Edges.StoragePolicies != nil {
			defaultID = group.Edges.StoragePolicies.ID
			if err := client.GroupPolicy.Create().SetGroupID(group.ID).SetStoragePolicyID(defaultID).SetPosition(0).Exec(ctx); err != nil {
				return err
			}
		}
		if group.StoragePolicyID == defaultID {
			continue
		}
		update := client.Group.UpdateOne(group)
		if defaultID > 0 {
			update.SetStoragePolicyID(defaultID)
		} else {
			update.ClearStoragePolicies()
		}
		if err := update.Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
