package controllers_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent/openidsession"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"github.com/stretchr/testify/require"
)

func TestOpenIDMarkedSessionsFailClosed(t *testing.T) {
	for _, damage := range []string{"missing", "ciphertext", "owner", "expired", "expires-mismatch"} {
		t.Run(damage, func(t *testing.T) {
			r, d, p, _, local := nativeFixture(t)
			target, proof := prepareExternal(t, r, 3, true, local.AccessToken)
			require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
			target, proof = prepareExternal(t, r, 3, false, "")
			w := finishExternal(t, r, p, target, proof)
			require.Zero(t, responseCode(t, w))
			var login struct{ Data struct{ Token auth.Token } }
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
			root, err := d.db.OpenIDSession.Query().Only(context.Background())
			require.NoError(t, err)
			switch damage {
			case "missing":
				err = d.db.OpenIDSession.DeleteOne(root).Exec(context.Background())
			case "ciphertext":
				err = d.db.OpenIDSession.UpdateOne(root).SetPayload([]byte("corrupt")).Exec(context.Background())
			case "owner":
				err = d.db.OpenIDSession.UpdateOne(root).ClearUserID().Exec(context.Background())
			case "expired":
				err = d.db.OpenIDSession.Update().Where(openidsession.RootID(root.RootID)).SetExpiresAt(time.Now().UTC().Add(-time.Minute)).Exec(context.Background())
			case "expires-mismatch":
				err = d.db.OpenIDSession.Update().Where(openidsession.RootID(root.RootID)).SetExpiresAt(root.ExpiresAt.Add(-time.Second)).Exec(context.Background())
			}
			require.NoError(t, err)
			w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": login.Data.Token.RefreshToken}, nil)
			require.NotZero(t, responseCode(t, w))
			require.NotContains(t, w.Body.String(), "access_token")
			// An ordinary native family remains usable regardless of the broken external row/config.
			require.NoError(t, d.SettingClient().Set(context.Background(), map[string]string{oidc.SettingName: "malformed"}))
			w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": local.RefreshToken}, nil)
			require.Zero(t, responseCode(t, w), w.Body.String())
		})
	}
}

func TestOpenIDPersistenceFailureNeverReturnsCredentials(t *testing.T) {
	for _, operation := range []string{"login", "refresh"} {
		t.Run(operation, func(t *testing.T) {
			r, d, p, _, local := nativeFixture(t)
			value, _ := authenticationDatabases.Load(d.db)
			database := value.(authenticationDatabase)
			if database.Driver != "sqlite3" {
				t.Skip("SQLite trigger injects a real persistence failure")
			}
			target, proof := prepareExternal(t, r, 3, true, local.AccessToken)
			require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
			var refresh string
			if operation == "refresh" {
				target, proof = prepareExternal(t, r, 3, false, "")
				w := finishExternal(t, r, p, target, proof)
				require.Zero(t, responseCode(t, w))
				var login struct{ Data struct{ Token auth.Token } }
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
				refresh = login.Data.Token.RefreshToken
				time.Sleep(1100 * time.Millisecond)
			}
			raw, err := sql.Open(database.Driver, database.DSN)
			require.NoError(t, err)
			defer raw.Close()
			event := "INSERT"
			if operation == "refresh" {
				event = "UPDATE"
			}
			_, err = raw.Exec("CREATE TRIGGER oidc_fixture_write_failure BEFORE " + event + " ON open_id_sessions BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END")
			require.NoError(t, err)
			var w *httptest.ResponseRecorder
			if operation == "login" {
				target, proof = prepareExternal(t, r, 3, false, "")
				w = finishExternal(t, r, p, target, proof)
			} else {
				w = openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": refresh}, nil)
			}
			require.NotZero(t, responseCode(t, w))
			require.NotContains(t, w.Body.String(), "access_token")
			require.NotContains(t, w.Body.String(), "refresh_token")
		})
	}
}
func TestOpenIDRefreshAndLogoutRaceRetainsMaximumExpiry(t *testing.T) {
	r, d, p, _, local := nativeFixture(t)
	target, proof := prepareExternal(t, r, 3, true, local.AccessToken)
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	target, proof = prepareExternal(t, r, 3, false, "")
	w := finishExternal(t, r, p, target, proof)
	require.Zero(t, responseCode(t, w))
	var login struct{ Data struct{ Token auth.Token } }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &login))
	original, err := d.db.OpenIDSession.Query().Only(context.Background())
	require.NoError(t, err)
	// Native refresh claims have second precision. Cross a second to exercise an
	// actual sliding extension without changing a previously issued expiry.
	time.Sleep(1100 * time.Millisecond)
	refresh := map[string]string{"refresh_token": login.Data.Token.RefreshToken}
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		wg.Add(1)
		go func(method string) {
			defer wg.Done()
			path := "/api/v4/session/token"
			if method == http.MethodPost {
				path += "/refresh"
			}
			responses <- openIDRequest(t, r, method, path, refresh, nil)
		}(method)
	}
	wg.Wait()
	close(responses)
	for response := range responses {
		if responseCode(t, response) == 0 {
			var result struct{ Data json.RawMessage }
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
			if len(result.Data) > 0 && result.Data[0] == '{' {
				var token auth.Token
				require.NoError(t, json.Unmarshal(result.Data, &token))
				require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", map[string]string{"refresh_token": token.RefreshToken}, nil)))
			}
		}
	}
	root, err := d.db.OpenIDSession.Query().Where(openidsession.RootID(original.RootID)).Only(context.Background())
	require.NoError(t, err)
	require.NotNil(t, root.RevokedAt)
	require.False(t, root.ExpiresAt.Before(original.ExpiresAt))
	require.Empty(t, root.Payload)
	require.NotZero(t, responseCode(t, openIDRequest(t, r, "POST", "/api/v4/session/token/refresh", refresh, nil)))
	require.NoError(t, d.o.Cleanup(context.Background()))
	require.True(t, d.db.OpenIDSession.Query().Where(openidsession.RootID(original.RootID)).ExistX(context.Background()))
	_, err = d.db.OpenIDSession.Update().Where(openidsession.RootID(root.RootID)).SetExpiresAt(time.Now().UTC().Add(-time.Minute)).Save(context.Background())
	require.NoError(t, err)
	require.NoError(t, d.o.Cleanup(context.Background()))
	require.False(t, d.db.OpenIDSession.Query().Where(openidsession.RootID(original.RootID)).ExistX(context.Background()))
}
