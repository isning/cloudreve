package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"os"
	"sync"
	"time"
)

type migrationDatabase struct {
	DB                  *sql.DB
	Dialect, SQLitePath string
}

var migrationDatabases sync.Map

// Production clients register the underlying connection so the extension DDL
// is serialized across processes, independently of its completion marker.
func externalMigrationLock(ctx context.Context, client *ent.Client) (func(), error) {
	value, ok := migrationDatabases.Load(client)
	if !ok {
		return func() {}, nil
	} // enttest uses the process mutex.
	database := value.(migrationDatabase)
	if database.Dialect == "sqlite" || database.Dialect == "sqlite3" {
		if database.SQLitePath == "" {
			return func() {}, nil
		}
		lock, err := os.OpenFile(database.SQLitePath+".oidc-migration.lock", os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("open extension migration lock: %w", err)
		}
		for {
			locked, err := tryExternalFileLock(lock)
			if err == nil && locked {
				return func() { _ = unlockExternalFile(lock); _ = lock.Close() }, nil
			}
			if err != nil {
				_ = lock.Close()
				return nil, err
			}
			select {
			case <-ctx.Done():
				_ = lock.Close()
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	conn, err := database.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if database.Dialect == "postgres" {
		_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock(1129467727, 1330201667)")
		if err == nil {
			return func() {
				_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock(1129467727, 1330201667)")
				_ = conn.Close()
			}, nil
		}
	} else {
		var locked int
		err = conn.QueryRowContext(ctx, "SELECT GET_LOCK(CONCAT(DATABASE(), ':cloudreve:oidc:v1'), 30)").Scan(&locked)
		if err == nil && locked == 1 {
			return func() {
				_, _ = conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK(CONCAT(DATABASE(), ':cloudreve:oidc:v1'))")
				_ = conn.Close()
			}, nil
		}
		if err == nil {
			err = fmt.Errorf("extension migration lock timed out")
		}
	}
	_ = conn.Close()
	return nil, err
}
