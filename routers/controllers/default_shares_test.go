package controllers_test

import (
	"context"
	"encoding/json"
	entgo "entgo.io/ent"
	"errors"
	"fmt"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/pkg/oidc"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/share"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) setDefaultShares(t *testing.T, ids ...int) {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	if ids == nil {
		ids = []int{}
	}
	raw, _ := json.Marshal(ids)
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": string(raw)}}, nil)
	f.login(t)
}
func (f *storageFixture) defaultShare(t *testing.T, name string) (int, string) {
	t.Helper()
	f.upload(t, "cloudreve://my/"+name+"/readme.txt", []byte("welcome"), nil)
	id, uri := f.createWritableShare(t, "cloudreve://my/"+name, map[string]any{"everyone": "IQ==", "anonymous": "IQ=="})
	n, err := f.dep.HashIDEncoder().Decode(id, hashid.ShareID)
	require.NoError(t, err)
	return n, uri
}
func TestDefaultSharesInitialSnapshotAndCurrentAddition(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "welcome-a")
	b, _ := f.defaultShare(t, "welcome-b")
	f.setDefaultShares(t, a, a)
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t, b)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	files := f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).WithMetadata().AllX(context.Background())
	require.Len(t, files, 1)
	require.Equal(t, "welcome-a", files[0].Name)
	require.Equal(t, 1, f.db.AuditLog.Query().Where(auditlog.Type(int(types.AuditMount)), auditlog.FileID(files[0].ID)).CountX(context.Background()))
	for _, meta := range files[0].Edges.Metadata {
		if meta.Name == "sys:shared_redirect" {
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(meta.Value), nil, &listing)
			require.Contains(t, listing.Parent.Path, "default_share_identity=")
		}
	}
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Added)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	fresh := f.db.User.GetX(context.Background(), visitor.ID)
	require.True(t, fresh.Settings.DefaultShares.Done)
	// A settings form loaded before materialization cannot reset completion.
	visitor.Settings.Language = "zh-CN"
	require.NoError(t, inventory.NewUserClient(f.db).SaveSettings(context.Background(), visitor))
	require.True(t, f.db.User.GetX(context.Background(), visitor.ID).Settings.DefaultShares.Done)

	f.login(t)
	f.setDefaultShares(t)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Zero(t, result.Existing)
	require.Zero(t, result.Skipped)
}

func TestDefaultSharesSettingsValidationAndAccess(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "settings")
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	for _, raw := range []string{"null", "{}", "[0]", "[-1]", "[1.5]", "[\"1\"]", "[999999999]", "[" + strings.Repeat("1,", 100) + "1]", "[" + strings.Repeat(" ", 8192) + "]"} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": raw}}), raw)
	}
	f.setDefaultShares(t, a, a)
	f.db.Share.DeleteOneID(a).ExecX(context.Background())
	f.setDefaultShares(t, a)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": "[]"}}))
}

func TestDefaultSharesSelfServicePrivacyAndRevocation(t *testing.T) {
	f := newWritableShareFixture(t)
	a, uri := f.defaultShare(t, "protected")
	visitor, password := f.createWritableVisitor(t, 2)
	// Keep automatic onboarding empty, then expose a current recommendation.
	f.setDefaultShares(t, a)
	f.loginAs(t, visitor.Email, password)
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", map[string]any{"ids": []int{a + 1}, "user_id": 1}, &result)
	require.Equal(t, 1, result.Added)
	f.login(t)
	f.db.Share.UpdateOneID(a).SetPassword("not-a-public-link").ExecX(context.Background())
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Skipped)
	require.Zero(t, result.Added)
	f.login(t)
	f.db.Share.UpdateOneID(a).SetPassword("").SetProps(&types.ShareProps{Permissions: &types.PermissionSetting{Everyone: types.ReadOnlyPermissions(), Anonymous: types.ReadOnlyPermissions()}}).ExecX(context.Background())
	f.request(t, http.MethodPost, fmt.Sprintf("/api/v4/share/%s", hashid.EncodeShareID(f.dep.HashIDEncoder(), a)), map[string]any{"uri": "cloudreve://my/protected", "permissions": map[string]string{"everyone": "AA==", "anonymous": "AA=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(uri), nil))
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Skipped)
	require.Equal(t, 1, f.db.Share.Query().Where(share.ID(a)).CountX(context.Background()))
}

func TestDefaultSharesUserOrganizationAndOldAccounts(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "organize")
	visitor, password := f.createWritableVisitor(t, 2)
	// Existing installations without an eligibility marker never auto-provision.
	f.db.User.UpdateOneID(visitor.ID).SetSettings(&types.UserSetting{Language: "zh-CN"}).ExecX(context.Background())
	f.setDefaultShares(t, a)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Empty(t, listing.Files)
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Added)
	f.request(t, http.MethodPost, "/api/v4/file/rename", map[string]any{"uri": "cloudreve://my/organize", "new_name": "renamed"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/moved", "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{"cloudreve://my/renamed"}, "dst": "cloudreve://my/moved"}, nil)
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/moved/renamed"}}, nil)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()), "login/list does not resurrect the shortcut")
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Added)
	require.Equal(t, "zh-CN", f.db.User.GetX(context.Background(), visitor.ID).Settings.Language)
	require.Nil(t, f.db.User.GetX(context.Background(), visitor.ID).Settings.DefaultShares)
}

func TestDefaultSharesNativeAccountCreation(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "onboarding")
	f.setDefaultShares(t, a)
	// The public registration API must capture the same snapshot as local inventory creation.
	email := "signup-" + storageRandom(t) + "@example.com"
	password := storageRandom(t)
	f.request(t, http.MethodPost, "/api/v4/user", map[string]any{"email": email, "password": password}, nil)
	f.loginAs(t, email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	adminEmail := "admin-created-" + storageRandom(t) + "@example.com"
	f.request(t, http.MethodPut, "/api/v4/admin/user", map[string]any{"user": map[string]any{"email": adminEmail, "nick": "New member", "status": "active", "group_users": 2}, "password": password}, nil)
	f.loginAs(t, adminEmail, password)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
}

func TestDefaultSharesConcurrentRequestsAndFailureRollback(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "atomic")
	f.setDefaultShares(t, a)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	// Fail the metadata write after a shortcut insert: neither may survive.
	var fail atomic.Bool
	f.db.Metadata.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if fail.Load() {
				return nil, errors.New("controlled shortcut failure")
			}
			return next.Mutate(ctx, m)
		})
	})
	fail.Store(true)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil))
	require.Zero(t, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
	fail.Store(false)
	first := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, "defaults-first")
	second := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, "defaults-second")
	automatic := f.permissionAsyncRequest(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, "defaults-automatic")
	require.Zero(t, awaitPermissionResult(t, first).Code)
	require.Zero(t, awaitPermissionResult(t, second).Code)
	require.Zero(t, awaitPermissionResult(t, automatic).Code)
	require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
}

func TestDefaultSharesConfigurationRemovalAtCommitBoundary(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "removed-current")
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t, a)
	f.loginAs(t, visitor.Email, password)
	reached, resume := pausePermissionFileRead(t, f, "removed-current", "paused-default-removal")
	pending := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, "paused-default-removal")
	awaitPermissionPause(t, reached)
	f.setDefaultShares(t)
	resume()
	require.Zero(t, awaitPermissionResult(t, pending).Code)
	require.Zero(t, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
}

func TestDefaultSharesNativeOIDCSignupSnapshot(t *testing.T) {
	r, d, p, _, _ := nativeFixture(t)
	// The identity provider protocol runs unchanged; no source links are required
	// to prove that JIT creates durable eligibility only once.
	changeProvider(t, d, func(registry *oidc.Registry) { registry.Providers[0].Config.DirectSignIn = true })
	p.email = "default-shares-jit@example.com"
	target, proof := prepareExternal(t, r, 3, false, "")
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	created, err := inventory.NewUserClient(d.db).GetByEmail(context.Background(), p.email)
	require.NoError(t, err)
	require.NotNil(t, created.Settings.DefaultShares)
	state, err := json.Marshal(created.Settings.DefaultShares)
	require.NoError(t, err)
	target, proof = prepareExternal(t, r, 3, false, "")
	require.Zero(t, responseCode(t, finishExternal(t, r, p, target, proof)))
	fresh, err := inventory.NewUserClient(d.db).GetByID(context.Background(), created.ID)
	require.NoError(t, err)
	unchanged, err := json.Marshal(fresh.Settings.DefaultShares)
	require.NoError(t, err)
	require.JSONEq(t, string(state), string(unchanged))
}

func TestDefaultSharesExistingAccountRestartsAndUserSettings(t *testing.T) {
	t.Setenv("CLOUDREVE_PERMISSION_FULL_ROUTER", "1")
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "restart")
	old, password := f.createWritableVisitor(t, 2)
	f.db.User.UpdateOneID(old.ID).SetSettings(&types.UserSetting{Language: "zh-CN"}).ExecX(context.Background())
	f.setDefaultShares(t, a)
	pending, pendingPassword := f.createWritableVisitor(t, 2)
	for i := 0; i < 2; i++ {
		worker := launchStorageWorker(t, f)
		f.remote = worker.ready(t)
		f.loginAs(t, old.Email, password)
		var listing explorer.ListResponse
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
		if i == 0 {
			require.Empty(t, listing.Files)
			var result inventory.DefaultShareResult
			f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
			require.Equal(t, 1, result.Added)
		} else {
			require.Len(t, listing.Files, 1)
		}
		f.loginAs(t, pending.Email, pendingPassword)
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
		require.Len(t, listing.Files, 1)
		worker.stop(t)
		f.remote = ""
	}
	require.Nil(t, f.db.User.GetX(context.Background(), old.ID).Settings.DefaultShares)
	require.Equal(t, "zh-CN", f.db.User.GetX(context.Background(), old.ID).Settings.Language)
}

func TestDefaultSharesPrivateNamesAndIdentityGuards(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/secret-source/readme.txt", []byte("private"), nil)
	var link string
	gate := storageRandom(t)[:8]
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/secret-source", "is_private": true, "password": gate, "permissions": map[string]string{"everyone": "IQ=="}}, &link)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	id, err := f.dep.HashIDEncoder().Decode(strings.Split(strings.TrimPrefix(parsed.Path, "/s/"), "/")[0], hashid.ShareID)
	require.NoError(t, err)
	f.setDefaultShares(t, id)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, "Shared resource", listing.Files[0].Name)
	require.NotContains(t, fmt.Sprint(listing.Files), gate)
	require.NotContains(t, fmt.Sprint(listing.Files), "secret-source")
	redirect := listing.Files[0].Metadata["sys:shared_redirect"]
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(redirect), nil), "native password gate remains")
	protected, err := url.Parse(redirect)
	require.NoError(t, err)
	protected.User = url.UserPassword(protected.User.Username(), gate)
	protected.Path = "/readme.txt"
	require.Equal(t, []byte("private"), f.readFile(t, protected.String()))
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Equal(t, 1, result.Skipped)
	// A different share incarnation must fail even if it is otherwise public.
	f.db.Share.UpdateOneID(id).SetPassword("").ExecX(context.Background())
	target, err := url.Parse(redirect)
	require.NoError(t, err)
	query := target.Query()
	query.Set("default_share_identity", "old-incarnation")
	target.RawQuery = query.Encode()
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(target.String()), nil))
}

func TestDefaultSharesInactiveActivationRetainsSnapshot(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "activated")
	f.setDefaultShares(t, a)
	password := storageRandom(t)
	pending, err := inventory.NewUserClient(f.db).Create(context.Background(), &inventory.NewUserArgs{Email: "inactive-" + storageRandom(t) + "@example.com", PlainPassword: password, Status: entuser.StatusInactive, GroupID: 2, SkipBootstrap: true})
	require.NoError(t, err)
	_, _, err = inventory.InstallDefaultShares(context.Background(), inventory.NewUserClient(f.db), pending.ID, f.dep.HashIDEncoder(), false)
	require.NoError(t, err)
	require.False(t, f.db.User.GetX(context.Background(), pending.ID).Settings.DefaultShares.Done)
	require.Zero(t, f.db.File.Query().Where(file.OwnerID(pending.ID), file.IsSymbolic(true)).CountX(context.Background()))
	f.setDefaultShares(t)
	f.db.User.UpdateOneID(pending.ID).SetStatus(entuser.StatusActive).ExecX(context.Background())
	f.loginAs(t, pending.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, "activated", listing.Files[0].Name)
}

func TestDefaultSharesBootstrapKeepsAdministratorAndEmptyEligibility(t *testing.T) {
	db := openAuthenticationDatabase(t, "default-shares-bootstrap.db")
	ctx := context.Background()
	for _, name := range []string{"Administrators", "Members"} {
		_, err := db.Group.Create().SetName(name).SetPermissions(&boolset.BooleanSet{}).Save(ctx)
		require.NoError(t, err)
	}
	first, err := inventory.NewUserClient(db).Create(ctx, &inventory.NewUserArgs{Email: "bootstrap@example.com", GroupID: 2, Status: entuser.StatusActive})
	require.NoError(t, err)
	saved := db.User.GetX(ctx, first.ID)
	require.Equal(t, 1, saved.GroupUsers)
	require.NotNil(t, saved.Settings.DefaultShares)
	require.Empty(t, saved.Settings.DefaultShares.Shares)
}

func TestDefaultSharesSingleFileAndIndependentLinks(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/guide.txt", []byte("single file guide"), nil)
	first, _ := f.createWritableShare(t, "cloudreve://my/guide.txt", map[string]any{"everyone": "IQ=="})
	second, _ := f.createWritableShare(t, "cloudreve://my/guide.txt", map[string]any{"everyone": "IQ=="})
	a, err := f.dep.HashIDEncoder().Decode(first, hashid.ShareID)
	require.NoError(t, err)
	b, err := f.dep.HashIDEncoder().Decode(second, hashid.ShareID)
	require.NoError(t, err)
	f.setDefaultShares(t, a, b)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 2)
	for _, entry := range listing.Files {
		require.Equal(t, int(types.FileTypeFile), entry.Type)
		require.Equal(t, []byte("single file guide"), f.readFile(t, entry.Metadata["sys:shared_redirect"]))
	}
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 2, result.Existing)
	require.NotEqual(t, listing.Files[0].Name, listing.Files[1].Name)
}

func TestDefaultSharesSignupAuditFailureRollsBackAccount(t *testing.T) {
	f := newWritableShareFixture(t)
	a, _ := f.defaultShare(t, "signup-rollback")
	f.setDefaultShares(t, a)
	var fail atomic.Bool
	f.db.AuditLog.Use(func(next entgo.Mutator) entgo.Mutator {
		return entgo.MutateFunc(func(ctx context.Context, m entgo.Mutation) (entgo.Value, error) {
			if fail.Load() {
				return nil, errors.New("controlled audit failure")
			}
			return next.Mutate(ctx, m)
		})
	})
	email := "rollback-" + storageRandom(t) + "@example.com"
	fail.Store(true)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/user", map[string]any{"email": email, "password": storageRandom(t)}))
	_, err := inventory.NewUserClient(f.db).GetByEmail(context.Background(), email)
	require.Error(t, err)
	fail.Store(false)
}

func TestDefaultSharesProtectedSingleFile(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/private.txt", []byte("protected single file"), nil)
	gate := storageRandom(t)[:8]
	var link string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/private.txt", "is_private": true, "password": gate, "permissions": map[string]string{"everyone": "IQ=="}}, &link)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	id, err := f.dep.HashIDEncoder().Decode(strings.Split(strings.TrimPrefix(parsed.Path, "/s/"), "/")[0], hashid.ShareID)
	require.NoError(t, err)
	f.setDefaultShares(t, id)
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
	require.Len(t, listing.Files, 1)
	redirect, err := url.Parse(listing.Files[0].Metadata["sys:shared_redirect"])
	require.NoError(t, err)
	require.NotEmpty(t, redirect.Query().Get("default_share_identity"))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(redirect.String()), nil))
	redirect.User = url.UserPassword(redirect.User.Username(), gate)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(redirect.String()), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.Equal(t, []byte("protected single file"), f.readFile(t, listing.Files[0].Path))
}

func TestDefaultSharesManualShortcutHostCase(t *testing.T) {
	f := newWritableShareFixture(t)
	id, redirect := f.defaultShare(t, "manual-host")
	visitor, password := f.createWritableVisitor(t, 2)
	f.setDefaultShares(t, id)
	f.loginAs(t, visitor.Email, password)
	parsed, err := url.Parse(redirect)
	require.NoError(t, err)
	parsed.Host = "ShArE"
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/saved-manually", "type": "folder", "metadata": map[string]string{"sys:shared_redirect": parsed.String()}}, nil)
	// The native parser accepts case-insensitive filesystem hosts.
	parsed.Path = "/readme.txt"
	require.Equal(t, []byte("welcome"), f.readFile(t, parsed.String()))
	var result inventory.DefaultShareResult
	f.request(t, http.MethodPost, "/api/v4/user/setting/default-shares", nil, &result)
	require.Zero(t, result.Added)
	require.Equal(t, 1, result.Existing)
	require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(visitor.ID), file.IsSymbolic(true)).CountX(context.Background()))
}

func TestDefaultSharesRepairInvalidConfiguration(t *testing.T) {
	f := newWritableShareFixture(t)
	id, _ := f.defaultShare(t, "repair-config")
	for _, key := range []string{"default_symbolics", "default_symbolics_identities"} {
		for _, replacement := range []string{"[]", fmt.Sprintf("[%d]", id)} {
			t.Run(key+replacement, func(t *testing.T) {
				f.setDefaultShares(t, id)
				require.NoError(t, f.db.Setting.Create().SetName(key).SetValue("null-invalid").OnConflictColumns("name").UpdateNewValues().Exec(context.Background()))
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
				// A malformed previous value must not let an invalid new ID bypass validation.
				require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": "[999999999]"}}))
				f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"default_symbolics": replacement}}, nil)
				f.login(t)
				visitor, password := f.createWritableVisitor(t, 2)
				f.loginAs(t, visitor.Email, password)
				var listing explorer.ListResponse
				f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my"), nil, &listing)
				expected := 0
				if replacement != "[]" {
					expected = 1
				}
				require.Len(t, listing.Files, expected)
			})
		}
	}
	// Repair tolerates invalid stored JSON, never database read failures.
	var fail atomic.Bool
	readFailure := errors.New("controlled settings read failure")
	f.db.Setting.Intercept(entgo.InterceptFunc(func(next entgo.Querier) entgo.Querier {
		return entgo.QuerierFunc(func(ctx context.Context, q entgo.Query) (entgo.Value, error) {
			if fail.Load() {
				return nil, readFailure
			}
			return next.Query(ctx, q)
		})
	}))
	uc, tx, ctx, err := inventory.WithTx(context.Background(), inventory.NewUserClient(f.db))
	require.NoError(t, err)
	fail.Store(true)
	_, err = inventory.SaveDefaultShares(ctx, uc.GetClient(), "[]")
	require.ErrorIs(t, err, readFailure)
	fail.Store(false)
	require.NoError(t, inventory.Rollback(tx))
	raw, err := inventory.NewSettingClient(f.db, nil).Get(context.Background(), "default_symbolics")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("[%d]", id), raw)

}
