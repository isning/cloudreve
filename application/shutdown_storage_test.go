package application

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/eventhub"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/stretchr/testify/require"
)

type shutdownStorageDep struct {
	dependency.Dep
	shutdown func(context.Context) error
}
type shutdownStorageHub struct{ eventhub.EventHub }

func (shutdownStorageHub) Close()                               {}
func (d shutdownStorageDep) EventHub() eventhub.EventHub        { return shutdownStorageHub{} }
func (d shutdownStorageDep) Shutdown(ctx context.Context) error { return d.shutdown(ctx) }

func TestServerShutdownPersistsCompletedReadsBeforeClosingSQL(t *testing.T) {
	ctx := context.Background()
	l := logging.NewConsoleLogger(logging.LevelError)
	cfg, err := conf.NewIniConfigProvider(filepath.Join(t.TempDir(), "conf.ini"), l)
	require.NoError(t, err)
	cfg.Database().Type = conf.SQLiteDB
	cfg.Database().DBFile = filepath.Join(t.TempDir(), "shutdown.db")
	db, err := inventory.NewRawEntClient(l, cfg)
	require.NoError(t, err)
	require.NoError(t, db.Schema.Create(ctx))
	completed, err := db.StorageObjectReader.Create().SetLocationKey("completed-read").Save(ctx)
	require.NoError(t, err)
	active, err := db.StorageObjectReader.Create().SetLocationKey("active-foreign-read").Save(ctx)
	require.NoError(t, err)
	var blocked atomic.Bool
	blocked.Store(true)
	db.StorageObjectReader.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if blocked.Load() {
				return nil, errors.New("controlled completion outage")
			}
			return next.Mutate(ctx, mutation)
		})
	})
	completions := inventory.NewStorageReadCompletions(db, l)
	t.Cleanup(func() { blocked.Store(false); completions.Close(ctx) })
	completions.ReaderFinished(completed.ID)
	var shutdownErr error
	var finished, untouched bool
	d := shutdownStorageDep{shutdown: func(ctx context.Context) error {
		blocked.Store(false)
		completions.Close(ctx)
		row, err := db.StorageObjectReader.Get(ctx, completed.ID)
		shutdownErr = err
		if err != nil {
			return err
		}
		finished = row.Finished
		row, err = db.StorageObjectReader.Get(ctx, active.ID)
		shutdownErr = err
		if err == nil {
			untouched = !row.Finished
		}
		return err
	}}
	s := &server{dep: d, dbClient: db, config: cfg, logger: l}
	s.Close()
	require.NoError(t, shutdownErr, "SQL remains available throughout actual server dependency shutdown")
	require.True(t, finished)
	require.True(t, untouched, "shutdown cannot manufacture completion evidence for another reader")
	_, err = db.StorageObjectReader.Get(ctx, completed.ID)
	require.Error(t, err, "SQL closes after acknowledgements drain")
}
