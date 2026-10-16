package controllers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsExpectedIdentityRejectsReplacement(t *testing.T) {
	f := newWritableShareFixture(t)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, batch := range []bool{false, true} {
			name := method + "-single"
			if batch {
				name = method + "-batch"
			}
			t.Run(name, func(t *testing.T) {
				base := "cloudreve://my/identity-" + name
				uri := base + "/selected.txt"
				f.upload(t, uri, []byte("original bytes"), nil)
				selected := f.permissionInfo(t, uri)
				uris, expected := []string{uri}, []string{selected.ID}
				if batch {
					other := base + "/untouched.txt"
					f.upload(t, other, []byte("untouched bytes"), nil)
					uris = append([]string{other}, uris...)
					expected = append([]string{f.permissionInfo(t, other).ID}, expected...)
				}
				// The editor's GET already returned A. A new file now occupies its URI
				// before the independently delivered permission write reaches the server.
				f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]string{"uri": uri, "new_name": "original.txt"}, nil)
				f.upload(t, uri, []byte("replacement bytes"), nil)
				require.NotEqual(t, selected.ID, f.permissionInfo(t, uri).ID)
				f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": uris, "setting": map[string]string{"everyone": "AA=="}}, nil)
				before := f.db.AuditLog.Query().CountX(context.Background())
				code := f.responseCode(t, method, "/api/v4/file/permission", map[string]any{
					"uris": uris, "expected_ids": expected, "setting": map[string]string{"everyone": "IQ=="},
				})
				require.Equal(t, serializer.CodeConflict, code)
				require.Equal(t, before, f.db.AuditLog.Query().CountX(context.Background()), "rejected batch must not add audit rows")
				for _, target := range uris {
					require.Equal(t, []byte{0}, []byte(*f.permissionInfo(t, target).ExtendedInfo.Permissions.Everyone))
				}
				require.Nil(t, f.permissionInfo(t, base+"/original.txt").ExtendedInfo.Permissions)
				require.Equal(t, []byte("replacement bytes"), f.readFile(t, uri))
				require.Equal(t, []byte("original bytes"), f.readFile(t, base+"/original.txt"))
			})
		}
	}
}

func TestFilePermissionsExpectedIdentityValidAndLegacy(t *testing.T) {
	f := newWritableShareFixture(t)
	a, b := "cloudreve://my/identity-valid/a.txt", "cloudreve://my/identity-valid/b.txt"
	f.upload(t, a, []byte("a"), nil)
	f.upload(t, b, []byte("b"), nil)
	aid, bid := f.permissionInfo(t, a).ID, f.permissionInfo(t, b).ID
	body := map[string]any{"uris": []string{a, b, a}, "expected_ids": []string{aid, bid, aid}, "setting": map[string]string{"everyone": "IQ=="}}
	f.request(t, http.MethodPost, "/api/v4/file/permission", body, nil)
	for _, uri := range []string{a, b} {
		require.Equal(t, []byte{33}, []byte(*f.permissionInfo(t, uri).ExtendedInfo.Permissions.Everyone))
	}
	f.request(t, http.MethodDelete, "/api/v4/file/permission", body, nil)
	for _, uri := range []string{a, b} {
		require.Nil(t, f.permissionInfo(t, uri).ExtendedInfo.Permissions)
	}
	// Conflicting expectations for a repeated object must not disappear when
	// the server deduplicates paths into one atomic target.
	body["expected_ids"] = []string{aid, bid, bid}
	require.Equal(t, serializer.CodeConflict, f.responseCode(t, http.MethodPost, "/api/v4/file/permission", body))
	require.Nil(t, f.permissionInfo(t, a).ExtendedInfo.Permissions)
	delete(body, "expected_ids")
	f.request(t, http.MethodPost, "/api/v4/file/permission", body, nil)
	f.request(t, http.MethodDelete, "/api/v4/file/permission", body, nil)
	require.Nil(t, f.permissionInfo(t, a).ExtendedInfo.Permissions, "legacy URI-only writes keep their native behavior")
}

func TestFilePermissionsExpectedIdentityValidation(t *testing.T) {
	f := newWritableShareFixture(t)
	uri := "cloudreve://my/identity-validation.txt"
	f.upload(t, uri, []byte("validation"), nil)
	id := f.permissionInfo(t, uri).ID
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, expected := range [][]string{{}, {id, id}, {""}, {"invalid"}, {hashid.EncodeGroupID(f.dep.HashIDEncoder(), 2)}} {
			require.Equal(t, serializer.CodeParamErr, f.responseCode(t, method, "/api/v4/file/permission", map[string]any{
				"uris": []string{uri}, "expected_ids": expected, "setting": map[string]string{"everyone": "AA=="},
			}))
			require.Nil(t, f.permissionInfo(t, uri).ExtendedInfo.Permissions)
		}
	}
}
