package migrator

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/application/migrator/model"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestGroupImportCreatesCanonicalBindingsAtomically(t *testing.T) {
	previous := model.DB
	source, err := gorm.Open("sqlite3", filepath.Join(t.TempDir(), "v3.db"))
	require.NoError(t, err)
	t.Cleanup(func() { model.DB = previous; require.NoError(t, source.Close()) })
	model.DB = source
	require.NoError(t, source.AutoMigrate(&model.Group{}).Error)
	require.NoError(t, source.Create(&model.Group{Name: "Imported group", Policies: "[2,1]", Options: "{}"}).Error)
	c := enttest.Open(t, "sqlite3", filepath.Join(t.TempDir(), "v4.db"))
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	ctx := context.Background()
	c.StoragePolicy.Create().SetName("A").SetType(types.PolicyTypeLocal).SaveX(ctx)
	c.StoragePolicy.Create().SetName("B").SetType(types.PolicyTypeLocal).SaveX(ctx)
	l := logging.NewConsoleLogger(logging.LevelError)
	cfg, err := conf.NewIniConfigProvider(filepath.Join(t.TempDir(), "conf.ini"), l)
	require.NoError(t, err)
	d := dependency.NewDependency(dependency.WithDbClient(c), dependency.WithConfigProvider(cfg))
	m := &Migrator{dep: d, v4client: c, l: l, state: &State{PolicyIDs: map[int]bool{1: true, 2: true}}}
	injected := errors.New("injected import binding failure")
	fail := true
	c.GroupPolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if fail {
				return nil, injected
			}
			return next.Mutate(ctx, mutation)
		})
	})
	require.ErrorIs(t, m.migrateGroup(), injected)
	require.Zero(t, c.Group.Query().CountX(ctx), "groups and their bindings roll back together")
	fail = false
	require.NoError(t, m.migrateGroup())
	g := c.Group.Query().OnlyX(ctx)
	require.Equal(t, 2, g.StoragePolicyID)
	grant := c.GroupPolicy.Query().Where(grouppolicy.GroupID(g.ID)).OnlyX(ctx)
	require.Equal(t, 2, grant.StoragePolicyID)
	require.Zero(t, grant.Position)
}
