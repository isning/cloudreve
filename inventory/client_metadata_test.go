package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestStorageCopyPlanningHasCapacityWhenTheTransactionPoolIsFull(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite uses the accepting transaction's only connection")
	}
	initial, raw, driver, connection := migrationFixture(t)
	require.NoError(t, initial.Close())
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	l := logging.NewConsoleLogger(logging.LevelError)
	config, err := conf.NewIniConfigProvider(filepath.Join(t.TempDir(), "conf.ini"), l)
	require.NoError(t, err)
	config.Database().Type = conf.DBType(driver)
	config.Database().DatabaseURL = connection.DSN
	c, err := NewRawEntClient(l, config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, c.Schema.Create(ctx))
	policy := c.StoragePolicy.Create().SetName("Copy destination").SetType(types.PolicyTypeLocal).SaveX(ctx)
	g := c.Group.Create().SetName("Copy owner group").SetPermissions(&boolset.BooleanSet{}).SaveX(ctx)
	u := c.User.Create().SetEmail("copy-owner@example.com").SetNick("Copy owner").SetGroupID(g.ID).SaveX(ctx)
	f := c.File.Create().SetName("").SetType(int(types.FileTypeFolder)).SetOwnerID(u.ID).SetStoragePolicyFiles(policy.ID).SaveX(ctx)
	value, ok := migrationDatabases.Load(c)
	require.True(t, ok)
	db := value.(migrationDatabase).DB
	db.SetMaxIdleConns(2)
	db.SetMaxOpenConns(2)
	writer, tx, txCtx, err := WithTx(ctx, NewStoragePolicyClient(c, nil))
	require.NoError(t, err)
	defer Rollback(tx)
	writer.GetClient().File.Query().CountX(txCtx)
	_, other, _, err := WithTx(ctx, NewStoragePolicyClient(c, nil))
	require.NoError(t, err)
	defer Rollback(other)
	require.Equal(t, 2, db.Stats().InUse)
	readCtx, stop := context.WithTimeout(txCtx, 3*time.Second)
	defer stop()
	require.NoError(t, LockCopyReferences(readCtx, writer.GetClient(), f.ID))
	require.Equal(t, 2, db.Stats().InUse, "planning must not wait for or consume a transaction-pool slot")
	metadata := CommittedMetadataClient(txCtx)
	require.NoError(t, Rollback(other))
	require.NoError(t, Rollback(tx))
	require.NoError(t, c.Close())
	_, err = metadata.File.Query().Count(ctx)
	require.Error(t, err, "closing the native client must also close its metadata connections")
}
