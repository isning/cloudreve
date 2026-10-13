package controllers_test

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	mysql "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type authenticationDatabase struct{ Driver, DSN string }

var authenticationDatabases sync.Map

// An opted-in database run creates a fresh database for each HTTP fixture inside
// the operator-owned disposable service; ordinary runs use isolated SQLite files.
func openAuthenticationDatabase(t *testing.T, name string) *ent.Client {
	return openAuthenticationDatabaseMode(t, name, true)
}

func openAuthenticationDatabaseMode(t *testing.T, name string, migrate bool) *ent.Client {
	t.Helper()
	open := func(driver, dsn string) *ent.Client {
		if migrate {
			return enttest.Open(t, driver, dsn)
		}
		client, err := ent.Open(driver, dsn)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, client.Close()) })
		return client
	}
	driver := os.Getenv("OIDC_TEST_DRIVER")
	dsn := os.Getenv("OIDC_TEST_DSN")
	if driver == "" {
		dsn = filepath.Join(t.TempDir(), name) + "?_pragma=busy_timeout(5000)"
		client := open("sqlite3", dsn)
		authenticationDatabases.Store(client, authenticationDatabase{"sqlite3", dsn})
		return client
	}
	require.Contains(t, []string{"postgres", "mysql"}, driver)
	require.NotEmpty(t, dsn, "OIDC_TEST_DSN is required for the database matrix")
	db, err := sql.Open(driver, dsn)
	require.NoError(t, err)
	defer db.Close()
	random := make([]byte, 8)
	_, err = rand.Read(random)
	require.NoError(t, err)
	database := "oidc_" + hex.EncodeToString(random)
	if driver == "postgres" {
		_, err = db.Exec(`CREATE DATABASE "` + database + `"`)
		require.NoError(t, err)
		target, err := url.Parse(dsn)
		require.NoError(t, err)
		target.Path = "/" + database
		dsn = target.String()
	} else {
		_, err = db.Exec("CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
		require.NoError(t, err)
		// ParseDSN preserves credentials without emitting the connection string.
		config, err := mysql.ParseDSN(dsn)
		require.NoError(t, err)
		config.DBName = database
		dsn = config.FormatDSN()
	}
	client := open(driver, dsn)
	authenticationDatabases.Store(client, authenticationDatabase{driver, dsn})
	return client
}
