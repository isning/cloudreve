package inventory

import (
	"context"
	"strings"
	"testing"

	"entgo.io/ent/dialect/sql/schema"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/stretchr/testify/require"
)

func TestAuditUpgradePreservesExistingDataAndConfiguration(t *testing.T) {
	ctx := context.Background()
	c, raw, _, _ := migrationFixture(t)
	defer raw.Close()
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	var previous []*schema.Table
	for _, table := range entmigrate.Tables {
		if !strings.HasPrefix(table.Name, "audit_") {
			previous = append(previous, table)
		}
	}
	require.NoError(t, entmigrate.Create(ctx, c.Schema, previous, schema.WithAtlas(false)))
	_, err := c.Setting.Create().SetName(DBVersionPrefix + "4.14.0").SetValue("installed").Save(ctx)
	require.NoError(t, err)
	_, err = c.Setting.Create().SetName("audit_record_ip").SetValue("0").Save(ctx)
	require.NoError(t, err)
	policy, err := c.StoragePolicy.Create().SetName("Existing storage").SetType(types.PolicyTypeS3).SetBucketName("existing-bucket").Save(ctx)
	require.NoError(t, err)
	require.NoError(t, EnsureAuditSchema(ctx, c))
	require.NoError(t, EnsureAuditSchema(ctx, c))
	require.Equal(t, "existing-bucket", c.StoragePolicy.GetX(ctx, policy.ID).BucketName)
	value, err := NewSettingClient(c, nil).Get(ctx, "audit_record_ip")
	require.NoError(t, err)
	require.Equal(t, "0", value)
	flags, err := NewSettingClient(c, nil).Get(ctx, "audit_enabled_flags")
	require.NoError(t, err)
	require.Equal(t, DefaultSettings["audit_enabled_flags"], flags)
	require.True(t, c.Setting.Query().Where(setting.Name(DBVersionPrefix+"4.14.0"), setting.Value("installed")).ExistX(ctx))
	log, err := c.AuditLog.Create().SetType(8).SetFileID(123).SetContent(&types.LogEntry{Category: types.AuditFileRename, OriginalName: "old", NewName: "new"}).Save(ctx)
	require.NoError(t, err)
	require.NoError(t, EnsureAuditSchema(ctx, c))
	require.Equal(t, "new", c.AuditLog.GetX(ctx, log.ID).Content.NewName)
	_, err = c.AuditArchive.Query().Count(ctx)
	require.NoError(t, err)
	_, err = c.AuditArchiveItem.Query().Count(ctx)
	require.NoError(t, err)
}
