package inventory

import (
	"context"
	"testing"

	"entgo.io/ent/dialect/sql/schema"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/stretchr/testify/require"
)

func TestLoadBalanceUpgradePreservesExistingStorageAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	c, raw, _, _ := migrationFixture(t)
	defer raw.Close()
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	var previous []*schema.Table
	for _, table := range entmigrate.Tables {
		if table.Name != "policy_load_balances" {
			previous = append(previous, table)
		}
	}
	require.NoError(t, entmigrate.Create(ctx, c.Schema, previous, schema.WithAtlas(false)))
	_, err := c.Setting.Create().SetName("storage_extension_schema_v8").SetValue("complete").Save(ctx)
	require.NoError(t, err)
	child, err := c.StoragePolicy.Create().SetName("Existing policy").SetType(types.PolicyTypeS3).SetBucketName("existing-bucket").SetSettings(&types.PolicySetting{Region: "us-east-1"}).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, EnsureStorageSchema(ctx, c))
	pool, err := c.StoragePolicy.Create().SetName("Pool after upgrade").SetType(types.PolicyTypeLoadBalance).Save(ctx)
	require.NoError(t, err)
	member, err := c.PolicyLoadBalance.Create().SetLoadBalanceID(pool.ID).SetStoragePolicyID(child.ID).SetWeight(3).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, EnsureStorageSchema(ctx, c))
	saved, err := c.PolicyLoadBalance.Get(ctx, member.ID)
	require.NoError(t, err)
	require.Equal(t, int64(3), saved.Weight)
	old, err := c.StoragePolicy.Get(ctx, child.ID)
	require.NoError(t, err)
	require.Equal(t, "existing-bucket", old.BucketName)
	require.Equal(t, child.Settings, old.Settings)
	complete, err := c.Setting.Query().Where(setting.Name(StorageSchemaVersion), setting.Value("complete")).Exist(ctx)
	require.NoError(t, err)
	require.True(t, complete)
}
