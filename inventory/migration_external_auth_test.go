package inventory

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	mysql "github.com/go-sql-driver/mysql"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect/sql/schema"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/externalidentity"
	entmigrate "github.com/cloudreve/Cloudreve/v4/ent/migrate"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/stretchr/testify/require"
)

// Build the previous schema, rather than upgrading an already-expanded database.
func TestExternalAuthUpgradePreservesLegacyDatabase(t *testing.T) {
	ctx := context.Background()
	c, raw, driver, _ := migrationFixture(t)
	defer raw.Close()
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	tables := legacyAuthenticationTables()
	require.NoError(t, entmigrate.Create(ctx, c.Schema, tables))
	_, err := c.Setting.Create().SetName("administrator_setting").SetValue("preserved").Save(ctx)
	require.NoError(t, err)
	group, err := c.Group.Create().SetName("Legacy group").SetPermissions(&boolset.BooleanSet{}).Save(ctx)
	require.NoError(t, err)
	password, err := digestPassword("legacy-password")
	require.NoError(t, err)
	query := "INSERT INTO users(created_at,updated_at,email,nick,password,status,settings,group_users) VALUES (?,?,?,?,?,?,?,?)"
	if driver == "postgres" {
		query = "INSERT INTO users(created_at,updated_at,email,nick,password,status,settings,group_users) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
	}
	_, err = raw.Exec(query, time.Now().UTC(), time.Now().UTC(), "legacy@example.com", "Legacy user", password, "active", "{}", group.ID)
	require.NoError(t, err)
	_, err = c.Setting.Create().SetName(DBVersionPrefix + "4.14.0").SetValue("installed").Save(ctx)
	require.NoError(t, err)
	require.NoError(t, EnsureExternalAuthSchema(ctx, c))
	require.NoError(t, EnsureExternalAuthSchema(ctx, c))
	value, err := NewSettingClient(c, nil).Get(ctx, "administrator_setting")
	require.NoError(t, err)
	require.Equal(t, "preserved", value)
	u, err := NewUserClient(c).GetByEmail(ctx, "legacy@example.com")
	require.NoError(t, err)
	require.False(t, u.SSOManaged)
	require.Equal(t, "Legacy user", u.Nick)
	require.Equal(t, group.ID, u.GroupUsers)
	require.NoError(t, CheckPassword(u, "legacy-password"))
	version, err := NewSettingClient(c, nil).Get(ctx, DBVersionPrefix+"4.14.0")
	require.NoError(t, err)
	require.Equal(t, "installed", version)
}

func TestExternalAuthFailedDDLCanResumeWithoutLosingData(t *testing.T) {
	c, raw, _, _ := migrationFixture(t)
	defer raw.Close()
	ctx := context.Background()
	tables := legacyAuthenticationTables()
	for i, table := range tables {
		if table.Name == "users" {
			tables[i] = entmigrate.UsersTable
		}
	}
	partial := *entmigrate.ExternalIdentitiesTable
	partial.Indexes = nil
	tables = append(tables, &partial)
	require.NoError(t, entmigrate.Create(ctx, c.Schema, tables))
	group, err := c.Group.Create().SetName("Existing group").SetPermissions(&boolset.BooleanSet{}).Save(ctx)
	require.NoError(t, err)
	u, err := c.User.Create().SetEmail("partial@example.com").SetNick("Existing user").SetPassword("preserved-hash").SetGroupUsers(group.ID).Save(ctx)
	require.NoError(t, err)
	for i, subject := range []string{"one", "two"} {
		_, err := c.ExternalIdentity.Create().SetIdentityKey(strings.Repeat(string(rune('a'+i)), 64)).SetProviderID(3).SetIssuer("https://idp.example").SetSubject(subject).SetUserID(u.ID).Save(ctx)
		require.NoError(t, err)
	}
	// The missing unique index cannot be added while this partial database has
	// conflicting slots. Failed DDL must not publish the completion marker.
	require.Error(t, EnsureExternalAuthSchema(ctx, c))
	require.False(t, c.Setting.Query().Where(setting.Name(ExternalAuthSchemaVersion)).ExistX(ctx))
	require.NoError(t, c.ExternalIdentity.Update().Where(externalidentity.Subject("two")).ClearUserID().SetState(externalidentity.StateUnlinked).Exec(ctx))
	require.NoError(t, EnsureExternalAuthSchema(ctx, c))
	require.Equal(t, "preserved-hash", c.User.GetX(ctx, u.ID).Password)
	require.Equal(t, 2, c.ExternalIdentity.Query().CountX(ctx))
}

func legacyAuthenticationTables() []*schema.Table {
	var tables []*schema.Table
	for _, table := range entmigrate.Tables {
		if table.Name == "external_identities" || table.Name == "open_id_transactions" || table.Name == "open_id_sessions" {
			continue
		}
		if table.Name == "users" {
			legacy := *table
			legacy.Columns = nil
			for _, col := range table.Columns {
				if col.Name != "sso_managed" {
					legacy.Columns = append(legacy.Columns, col)
				}
			}
			table = &legacy
		}
		tables = append(tables, table)
	}
	return tables
}

type migrationConnection struct{ Driver, DSN, Path string }

func migrationFixture(t *testing.T) (*ent.Client, *sql.DB, string, migrationConnection) {
	t.Helper()
	driver, dsn := os.Getenv("OIDC_TEST_DRIVER"), os.Getenv("OIDC_TEST_DSN")
	path := ""
	if driver == "" {
		driver = "sqlite3"
		path = filepath.Join(t.TempDir(), "migration.db")
		dsn = path + "?_pragma=busy_timeout(5000)"
	} else {
		admin, err := sql.Open(driver, dsn)
		require.NoError(t, err)
		defer admin.Close()
		suffix := make([]byte, 8)
		_, err = rand.Read(suffix)
		require.NoError(t, err)
		name := "oidc_migration_" + hex.EncodeToString(suffix)
		if driver == "postgres" {
			_, err = admin.Exec(`CREATE DATABASE "` + name + `"`)
			require.NoError(t, err)
			target, err := url.Parse(dsn)
			require.NoError(t, err)
			target.Path = "/" + name
			dsn = target.String()
		} else {
			require.Equal(t, "mysql", driver)
			_, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
			require.NoError(t, err)
			target, err := mysql.ParseDSN(dsn)
			require.NoError(t, err)
			target.DBName = name
			dsn = target.FormatDSN()
		}
	}
	raw, err := sql.Open(driver, dsn)
	require.NoError(t, err)
	dialect := driver
	if dialect == "sqlite3" {
		dialect = "sqlite3"
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect, raw)))
	migrationDatabases.Store(client, migrationDatabase{DB: raw, Dialect: driver, SQLitePath: path})
	t.Cleanup(func() { migrationDatabases.Delete(client) })
	return client, raw, driver, migrationConnection{driver, dsn, path}
}

func TestExternalAuthPartialInitializationCanResume(t *testing.T) {
	c, raw, _, _ := migrationFixture(t)
	defer raw.Close()
	ctx := context.Background()
	require.NoError(t, c.Schema.Create(ctx))
	t.Setenv(EnvDefaultOverwritePrefix+"external_login_providers", "broken")
	require.Error(t, EnsureExternalAuthSchema(ctx, c))
	require.False(t, c.Setting.Query().Where(setting.Name(ExternalAuthSchemaVersion)).ExistX(ctx))
	require.NoError(t, os.Unsetenv(EnvDefaultOverwritePrefix+"external_login_providers"))
	require.NoError(t, EnsureExternalAuthSchema(ctx, c))
	require.True(t, c.Setting.Query().Where(setting.Name(ExternalAuthSchemaVersion), setting.Value("complete")).ExistX(ctx))
}

func TestExternalAuthMigrationWorker(t *testing.T) {
	file := os.Getenv("OIDC_MIGRATION_PROCESS")
	if file == "" {
		t.Skip("subprocess migration worker")
	}
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	var config migrationConnection
	require.NoError(t, json.Unmarshal(data, &config))
	raw, err := sql.Open(config.Driver, config.DSN)
	require.NoError(t, err)
	defer raw.Close()
	dialect := config.Driver
	if dialect == "sqlite3" {
		dialect = "sqlite3"
	}
	c := ent.NewClient(ent.Driver(entsql.OpenDB(dialect, raw)))
	migrationDatabases.Store(c, migrationDatabase{DB: raw, Dialect: config.Driver, SQLitePath: config.Path})
	require.NoError(t, os.WriteFile(file+".started", []byte("started"), 0600))
	require.NoError(t, EnsureExternalAuthSchema(context.Background(), c))
	require.NoError(t, os.WriteFile(file+".complete", []byte("complete"), 0600))
}

func TestExternalAuthMigrationCoordinatesProcesses(t *testing.T) {
	c, raw, _, config := migrationFixture(t)
	defer raw.Close()
	ctx := context.Background()
	// Settings exist on an installed instance before this independent extension.
	require.NoError(t, entmigrate.Create(ctx, c.Schema, legacyAuthenticationTables()))
	unlock, err := externalMigrationLock(ctx, c)
	require.NoError(t, err)
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	data, err := json.Marshal(config)
	require.NoError(t, err)
	var commands []*exec.Cmd
	var files []string
	for i := 0; i < 2; i++ {
		file := filepath.Join(t.TempDir(), "worker.json")
		require.NoError(t, os.WriteFile(file, data, 0600))
		files = append(files, file)
		cmd := exec.Command(os.Args[0], "-test.run=^TestExternalAuthMigrationWorker$", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "OIDC_MIGRATION_PROCESS="+file)
		require.NoError(t, cmd.Start())
		commands = append(commands, cmd)
	}
	for _, file := range files {
		deadline := time.Now().Add(20 * time.Second)
		for {
			if _, err := os.Stat(file + ".started"); err == nil {
				break
			}
			require.True(t, time.Now().Before(deadline))
			time.Sleep(20 * time.Millisecond)
		}
	}
	time.Sleep(150 * time.Millisecond)
	for _, file := range files {
		_, err := os.Stat(file + ".complete")
		require.True(t, os.IsNotExist(err), "worker bypassed the held database migration lock")
	}
	unlock()
	unlock = nil
	for _, cmd := range commands {
		require.NoError(t, cmd.Wait())
	}
	require.NoError(t, EnsureExternalAuthSchema(ctx, c))
	require.Equal(t, 1, c.Setting.Query().Where(setting.Name(ExternalAuthSchemaVersion)).CountX(ctx))
	_, err = c.OpenIDTransaction.Query().Limit(1).All(ctx)
	require.NoError(t, err)
}
