package controllers_test

import (
	"context"
	entgo "entgo.io/ent"
	"errors"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) permissionInfo(t *testing.T, uri string) explorer.FileResponse {
	t.Helper()
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	return info
}

func TestFilePermissionsAtomicBatchAndExplicitEmpty(t *testing.T) {
	f := newWritableShareFixture(t)
	a, b := "cloudreve://my/batch/a.txt", "cloudreve://my/batch/folder"
	f.upload(t, a, []byte("original"), nil)
	f.upload(t, b+"/child.txt", []byte("child"), nil)
	setter := func(uris []string, setting any) int {
		return f.responseCode(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": uris, "setting": setting})
	}
	require.Zero(t, setter([]string{a, b, a}, map[string]string{"everyone": "IQ=="}), "duplicates must not conflict on their own lock")
	for _, uri := range []string{a, b} {
		info := f.permissionInfo(t, uri)
		require.NotNil(t, info.ExtendedInfo.Permissions)
		require.Equal(t, []byte{0x21}, []byte(*info.ExtendedInfo.Permissions.Everyone))
	}

	countActivities := func(uri string) int {
		var response explorer.FileActivitiesResponse
		f.request(t, http.MethodGet, "/api/v4/file/activities?page_size=100&uri="+url.QueryEscape(uri), nil, &response)
		count := 0
		for _, a := range response.Activities {
			if a.Content.Category == 9 {
				count++
			}
		}
		return count
	}
	require.Equal(t, 1, countActivities(a))
	require.Zero(t, setter([]string{a, b, a}, map[string]string{"everyone": "IQ=="}))
	require.Equal(t, 1, countActivities(a), "unchanged rules must not manufacture activity")
	var fail atomic.Bool
	bid, err := f.dep.HashIDEncoder().Decode(f.permissionInfo(t, b).ID, hashid.FileID)
	require.NoError(t, err)
	f.db.File.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, mutation entgo.Mutation) (entgo.Value, error) {
			if m, ok := mutation.(*ent.FileMutation); ok && fail.Load() {
				if id, ok := m.ID(); ok && id == bid {
					return nil, errors.New("controlled batch failure")
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	fail.Store(true)
	require.NotZero(t, setter([]string{a, b}, map[string]string{"everyone": "AA=="}))
	fail.Store(false)
	require.Equal(t, []byte{0x21}, []byte(*f.permissionInfo(t, a).ExtendedInfo.Permissions.Everyone))
	require.Equal(t, 1, countActivities(a), "an aborted batch must roll back its activity")
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	f.upload(t, "cloudreve://my/foreign.txt", []byte("foreign"), nil)
	_, foreignShare := f.createWritableShare(t, "cloudreve://my/foreign.txt", map[string]any{"everyone": "Lw=="})
	f.login(t)
	require.NotZero(t, setter([]string{a, foreignShare}, map[string]string{"everyone": "AA=="}))
	require.Equal(t, []byte{0x21}, []byte(*f.permissionInfo(t, a).ExtendedInfo.Permissions.Everyone))
	for _, invalid := range []any{nil, map[string]string{"everyone": "/w=="}, map[string]any{"user_explicit": map[string]string{"bad-id": "IQ=="}}} {
		require.NotZero(t, setter([]string{a, b}, invalid))
	}
	require.Zero(t, setter([]string{a, b}, map[string]any{}))
	require.NotNil(t, f.permissionInfo(t, a).ExtendedInfo.Permissions, "an explicit empty object is different from inheritance")
	f.request(t, http.MethodDelete, "/api/v4/file/permission", map[string]any{"uris": []string{a, b, a}}, nil)
	require.Nil(t, f.permissionInfo(t, a).ExtendedInfo.Permissions)
	require.Nil(t, f.permissionInfo(t, b).ExtendedInfo.Permissions)
	require.Equal(t, []byte("original"), f.readFile(t, a))
	require.Equal(t, []byte("child"), f.readFile(t, b+"/child.txt"))
}

func TestFilePermissionsManagerDiagnosticsDoNotLeakRules(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/diagnostics/file.txt", []byte("diagnostic bytes"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/diagnostics/file.txt"}, "setting": map[string]string{"everyone": "IQ=="}}, nil)
	info := f.permissionInfo(t, "cloudreve://my/diagnostics/file.txt")
	require.NotNil(t, info.ExtendedInfo.PermissionContext)
	require.Equal(t, "ccsn", info.ExtendedInfo.PermissionContext.Extension)
	require.Equal(t, "explicit", info.ExtendedInfo.PermissionContext.Source)
	require.Equal(t, []byte{0x3f}, []byte(*info.ExtendedInfo.PermissionContext.Effective))
	_, uri := f.createWritableShare(t, "cloudreve://my/diagnostics", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	recipient := f.permissionInfo(t, uri+"/file.txt")
	require.Nil(t, recipient.ExtendedInfo.PermissionContext)
	require.Nil(t, recipient.ExtendedInfo.Permissions)
	require.Equal(t, []byte{0x21}, []byte(*recipient.Permission))
}

func TestFilePermissionsSourcesStopAtLinkRoot(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/source-context/nested/file.txt", []byte("context bytes"), nil)
	for _, uri := range []string{"cloudreve://my/source-context", "cloudreve://my/source-context/nested"} {
		f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{uri}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	}
	_, uri := f.createWritableShare(t, "cloudreve://my/source-context", map[string]any{"everyone": "IQ=="})
	root := f.permissionInfo(t, uri).ExtendedInfo.PermissionContext
	require.Equal(t, "link", root.Source)
	require.NotContains(t, root.SourceURI, "my")
	child := f.permissionInfo(t, uri+"/nested/file.txt").ExtendedInfo.PermissionContext
	require.Equal(t, "ancestor", child.Source)
	require.Equal(t, uri+"/nested", child.SourceURI)
	direct := f.permissionInfo(t, "cloudreve://my/source-context/nested/file.txt").ExtendedInfo.PermissionContext
	require.Equal(t, "ancestor", direct.Source)
	require.True(t, direct.ContextDependent)
	f.request(t, http.MethodDelete, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/source-context/nested"}}, nil)
	require.Equal(t, "link", f.permissionInfo(t, uri+"/nested/file.txt").ExtendedInfo.PermissionContext.Source)
	_, single := f.createWritableShare(t, "cloudreve://my/source-context/nested/file.txt", map[string]any{"everyone": "IQ=="})
	require.Equal(t, "link", f.permissionInfo(t, single+"/file.txt").ExtendedInfo.PermissionContext.Source)
}

func TestFilePermissionsPersonalDiagnosticsRemainEntryDependent(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/multi-entry/child/file.txt", []byte("entry bytes"), nil)
	_, outer := f.createWritableShare(t, "cloudreve://my/multi-entry", map[string]any{"everyone": "IQ=="})
	_, inner := f.createWritableShare(t, "cloudreve://my/multi-entry/child", map[string]any{"everyone": "BA=="})
	own := f.permissionInfo(t, "cloudreve://my/multi-entry/child")
	require.True(t, own.ExtendedInfo.PermissionContext.ContextDependent)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	require.Equal(t, []byte("entry bytes"), f.readFile(t, outer+"/child/file.txt"))
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{inner + "/file.txt"}}))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file/info?uri="+url.QueryEscape("cloudreve://my/multi-entry/child"), nil))
}

func TestFilePermissionsReadAndListRemainIndependent(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/operation-matrix/file.txt", []byte("operation bytes"), nil)
	_, listOnly := f.createWritableShare(t, "cloudreve://my/operation-matrix", map[string]any{"everyone": "IA=="})
	_, readOnly := f.createWritableShare(t, "cloudreve://my/operation-matrix", map[string]any{"everyone": "AQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	for _, uri := range []string{listOnly, readOnly} {
		var listing explorer.ListResponse
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil, &listing)
		require.Len(t, listing.Files, 1)
		require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/new.txt", "size": 1}))
		require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri + "/file.txt", "entity_type": "version", "size": 1}))
		require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{uri + "/file.txt"}}))
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": uri + "/file.txt", "new_name": "changed.txt"}))
	}
	info := f.permissionInfo(t, listOnly+"/file.txt")
	require.Equal(t, []byte{0x20}, []byte(*info.Permission))
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{listOnly + "/file.txt"}}))
	require.Equal(t, []byte("operation bytes"), f.readFile(t, readOnly+"/file.txt"))
}
