package controllers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"entgo.io/ent/dialect/sql"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entshare "github.com/cloudreve/Cloudreve/v4/ent/share"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) setPermissionDiscovery(t *testing.T, enabled bool) {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	value := "0"
	if enabled {
		value = "1"
	}
	f.request(t, http.MethodPatch, "/api/v4/admin/settings", map[string]any{"settings": map[string]string{"shared_with_me_acl": value}}, nil)
}
func (f *storageFixture) discoverPermissionShares(t *testing.T, token string, size int) explorer.ListResponse {
	t.Helper()
	query := url.Values{"uri": {"cloudreve://shared_with_me"}, "page_size": {fmt.Sprint(size)}}
	if token != "" {
		query.Set("next_page_token", token)
	}
	var res explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?"+query.Encode(), nil, &res)
	return res
}
func TestFilePermissionsDiscoveryConfigurationAndEntry(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/discovered/hello.txt", []byte("discover actual bytes"), nil)
	_, shareURI := f.createWritableShare(t, "cloudreve://my/discovered", map[string]any{"everyone": "IQ==", "anonymous": "AA=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	var cfg struct {
		Enabled bool `json:"shared_with_me_acl"`
	}
	f.request(t, http.MethodGet, "/api/v4/site/config/explorer", nil, &cfg)
	require.False(t, cfg.Enabled)
	require.Empty(t, f.discoverPermissionShares(t, "", 20).Files, "missing setting keeps manual shortcuts")
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodGet, "/api/v4/site/config/explorer", nil, &cfg)
	require.True(t, cfg.Enabled)
	result := f.discoverPermissionShares(t, "", 20)
	require.Len(t, result.Files, 1)
	file := result.Files[0]
	require.True(t, strings.HasPrefix(file.ID, "share:"))
	require.False(t, file.Owned)
	require.Empty(t, file.PrimaryEntity)
	require.Equal(t, shareURI, file.Metadata[dbfs.MetadataSharedRedirect])
	require.Equal(t, []byte("discover actual bytes"), f.readFile(t, file.Metadata[dbfs.MetadataSharedRedirect]+"/hello.txt"))
	require.Zero(t, result.Pagination.TotalItems)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		body := map[string]any{"uris": []string{file.Path}, "setting": map[string]string{"everyone": "Pw=="}}
		require.NotZero(t, f.responseCode(t, method, "/api/v4/file/permission", body))
	}
	f.setPermissionDiscovery(t, false)
	f.loginAs(t, visitor.Email, password)
	require.Empty(t, f.discoverPermissionShares(t, "", 20).Files)
}

func TestFilePermissionsDiscoveryAudienceAndCurrentGroup(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/audiences/file.txt", []byte("audiences"), nil)
	visitor, password := f.createWritableVisitor(t, 2)
	uid := hashid.EncodeUserID(f.dep.HashIDEncoder(), visitor.ID)
	gid := hashid.EncodeGroupID(f.dep.HashIDEncoder(), 2)
	cases := []struct {
		setting map[string]any
		visible bool
	}{
		{map[string]any{"everyone": "IQ=="}, true},
		{map[string]any{"everyone": "IQ==", "user_explicit": map[string]string{uid: "AA=="}}, false},
		{map[string]any{"everyone": "AA==", "group_explicit": map[string]string{gid: "IQ=="}}, true},
		{map[string]any{"everyone": "AA==", "same_group": "IQ=="}, true},
		{map[string]any{"everyone": "AA==", "other": "IQ=="}, false},
		{map[string]any{"everyone": "IQ==", "user_explicit": map[string]string{uid: "BA=="}}, false},
		{map[string]any{"everyone": "BA=="}, false},
		{map[string]any{"everyone": "AA=="}, false},
		{map[string]any{}, true},
	}
	expected := map[string]bool{}
	for _, c := range cases {
		_, uri := f.createWritableShare(t, "cloudreve://my/audiences", c.setting)
		expected[uri] = c.visible
	}
	originalGroup := f.db.Group.GetX(context.Background(), 2)
	foreignGroup, err := f.db.Group.Create().SetName("Different creator group").SetPermissions(originalGroup.Permissions).SetSettings(originalGroup.Settings).SetMaxStorage(originalGroup.MaxStorage).SetStoragePolicyID(f.policies[0].ID).Save(context.Background())
	require.NoError(t, err)
	_, err = f.db.GroupPolicy.Create().SetGroupID(foreignGroup.ID).SetStoragePolicyID(f.policies[0].ID).SetPosition(0).Save(context.Background())
	require.NoError(t, err)
	delegate, delegatePassword := f.createWritableVisitor(t, foreignGroup.ID)
	_, delegationEntry := f.createWritableShare(t, "cloudreve://my/audiences", map[string]any{"everyone": "Pw=="})
	f.loginAs(t, delegate.Email, delegatePassword)
	_, delegated := f.createWritableShare(t, delegationEntry, map[string]any{"everyone": "AA==", "same_group": "IQ==", "other": "AA=="})
	expected[delegationEntry] = true
	expected[delegated] = true
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, visitor.Email, password)
	result := f.discoverPermissionShares(t, "", 50)
	found := map[string]bool{}
	for _, file := range result.Files {
		found[file.Metadata[dbfs.MetadataSharedRedirect]] = true
	}
	for uri, visible := range expected {
		require.Equal(t, visible, found[uri], "audience discovery mismatch")
	}
	require.Equal(t, []byte("audiences"), f.readFile(t, delegated+"/file.txt"), "same-group is relative to the actual file owner")
	noAccess := append(boolset.BooleanSet(nil), (*originalGroup.Permissions)...)
	boolset.Set(types.GroupPermissionShareDownload, false, &noAccess)
	require.NoError(t, f.db.Group.UpdateOneID(2).SetPermissions(&noAccess).Exec(context.Background()))
	require.Empty(t, f.discoverPermissionShares(t, "", 50).Files)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(delegated), nil))
	f.login(t)
	require.Len(t, f.discoverPermissionShares(t, "", 50).Files, len(expected), "actual owners keep access to their own links")
}

func TestFilePermissionsDiscoveryLockedAndIndependentSingleFileLinks(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/single/secret.txt", []byte("single object bytes"), nil)
	password := storageRandom(t)
	var link string
	f.request(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": "cloudreve://my/single/secret.txt", "password": password, "is_private": true, "permissions": map[string]string{"everyone": "IQ=="}}, &link)
	parsed, err := url.Parse(link)
	require.NoError(t, err)
	lockedID := strings.Split(strings.TrimPrefix(parsed.Path, "/s/"), "/")[0]
	_, otherURI := f.createWritableShare(t, "cloudreve://my/single/secret.txt", map[string]any{"everyone": "IQ=="})
	visitor, visitorPassword := f.createWritableVisitor(t, 2)
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, visitor.Email, visitorPassword)
	result := f.discoverPermissionShares(t, "", 20)
	require.Len(t, result.Files, 2)
	require.NotEqual(t, result.Files[0].ID, result.Files[1].ID)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), password)
	require.NotContains(t, string(encoded), "cloudreve://my")
	lockedURI := fs.NewShareUri(lockedID, "")
	var locked *explorer.FileResponse
	for i := range result.Files {
		if result.Files[i].Metadata[dbfs.MetadataSharedRedirect] == lockedURI {
			locked = &result.Files[i]
		}
	}
	require.NotNil(t, locked)
	require.Equal(t, "1", locked.Metadata["sys:shared_locked"])
	require.Zero(t, locked.Size)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(lockedURI), nil))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(fs.NewShareUri(lockedID, "wrong")), nil))
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(fs.NewShareUri(lockedID, password)), nil, &listing)
	require.True(t, listing.SingleFileView)
	require.Len(t, listing.Files, 1)
	require.Equal(t, []byte("single object bytes"), f.readFile(t, listing.Files[0].Path))
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(otherURI), nil, &listing)
	require.Len(t, listing.Files, 1)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": otherURI + "/sibling", "type": "folder"}))
	again := f.discoverPermissionShares(t, "", 20)
	require.Equal(t, result.Files[0].ID, again.Files[0].ID)
	require.Equal(t, result.Files[1].ID, again.Files[1].ID)
}

func TestFilePermissionsDiscoverySparseBudgetAndCursorIsolation(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/sparse/file.txt", []byte("sparse"), nil)
	fileID, err := f.dep.HashIDEncoder().Decode(f.fileInfo(t, "cloudreve://my/sparse").ID, hashid.FileID)
	require.NoError(t, err)
	builds := make([]*ent.ShareCreate, 0, 1005)
	for i := 0; i < 1005; i++ {
		grant := &boolset.BooleanSet{0}
		if i >= 1001 {
			grant = types.ReadOnlyPermissions()
		}
		builds = append(builds, f.db.Share.Create().SetUserID(2).SetFileID(fileID).SetProps(&types.ShareProps{Permissions: &types.PermissionSetting{Everyone: grant}}))
	}
	require.NoError(t, f.db.Share.CreateBulk(builds...).Exec(context.Background()))
	visitor, password := f.createWritableVisitor(t, 2)
	another, otherPassword := f.createWritableVisitor(t, 2)
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, visitor.Email, password)
	first := f.discoverPermissionShares(t, "", 10)
	require.Empty(t, first.Files)
	require.NotEmpty(t, first.Pagination.NextPageToken)
	require.Zero(t, first.Pagination.TotalItems)
	raw, err := base64.RawURLEncoding.DecodeString(first.Pagination.NextPageToken)
	require.NoError(t, err)
	require.False(t, json.Valid(raw), "continuation must not disclose a denied link identity")
	f.loginAs(t, another.Email, otherPassword)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri=cloudreve://shared_with_me&next_page_token="+url.QueryEscape(first.Pagination.NextPageToken), nil))
	f.loginAs(t, visitor.Email, password)
	raw[len(raw)-1] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri=cloudreve://shared_with_me&next_page_token="+url.QueryEscape(tampered), nil))
	for _, queryCase := range []struct{ uri, extra string }{{"cloudreve://shared_with_me", "&order_direction=desc"}, {"cloudreve://shared_with_me?name=changed", ""}} {
		query := "/api/v4/file?uri=" + url.QueryEscape(queryCase.uri) + "&next_page_token=" + url.QueryEscape(first.Pagination.NextPageToken) + queryCase.extra
		require.NotZero(t, f.responseCode(t, http.MethodGet, query, nil))
	}
	f.setPermissionDiscovery(t, false)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri=cloudreve://shared_with_me&next_page_token="+url.QueryEscape(first.Pagination.NextPageToken), nil))
	f.setPermissionDiscovery(t, true)
	f.login(t)
	last := f.db.Share.Query().Order(entshare.ByID(sql.OrderDesc())).FirstX(context.Background())
	f.request(t, http.MethodPost, "/api/v4/share/"+hashid.EncodeShareID(f.dep.HashIDEncoder(), last.ID), map[string]any{"uri": "cloudreve://my/sparse", "permissions": map[string]string{"everyone": "AA=="}}, nil)
	f.loginAs(t, visitor.Email, password)
	second := f.discoverPermissionShares(t, first.Pagination.NextPageToken, 10)
	require.Len(t, second.Files, 3)
	require.Empty(t, second.Pagination.NextPageToken)
	seen := map[string]bool{}
	for _, row := range second.Files {
		require.False(t, seen[row.ID])
		seen[row.ID] = true
	}
}

func TestFilePermissionsDiscoveryRejectsExpiredOrRecycledSources(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/live/file.txt", []byte("live"), nil)
	f.upload(t, "cloudreve://my/recycle/inside/file.txt", []byte("recycled"), nil)
	_, valid := f.createWritableShare(t, "cloudreve://my/live", map[string]any{"everyone": "Pw=="})
	expiredID, expired := f.createWritableShare(t, "cloudreve://my/live", map[string]any{"everyone": "IQ=="})
	exhaustedID, exhausted := f.createWritableShare(t, "cloudreve://my/live", map[string]any{"everyone": "IQ=="})
	deletedID, deleted := f.createWritableShare(t, "cloudreve://my/live", map[string]any{"everyone": "IQ=="})
	_, recycled := f.createWritableShare(t, "cloudreve://my/recycle/inside", map[string]any{"everyone": "IQ=="})
	creator, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, creator.Email, password)
	delegatedID, delegated := f.createWritableShare(t, valid, map[string]any{"everyone": "IQ=="})
	f.login(t)
	id := func(raw string) int {
		i, err := f.dep.HashIDEncoder().Decode(raw, hashid.ShareID)
		require.NoError(t, err)
		return i
	}
	past := time.Now().Add(-time.Minute)
	require.NoError(t, f.db.Share.UpdateOneID(id(expiredID)).SetExpires(past).Exec(context.Background()))
	require.NoError(t, f.db.Share.UpdateOneID(id(exhaustedID)).SetRemainDownloads(0).Exec(context.Background()))
	f.request(t, http.MethodDelete, "/api/v4/share/"+deletedID, nil, nil)
	f.request(t, http.MethodDelete, "/api/v4/file", map[string]any{"uris": []string{"cloudreve://my/recycle"}}, nil)
	require.NoError(t, f.db.User.UpdateOneID(creator.ID).SetStatus(entuser.StatusInactive).Exec(context.Background()))
	recipient, recipientPassword := f.createWritableVisitor(t, 2)
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, recipient.Email, recipientPassword)
	result := f.discoverPermissionShares(t, "", 50)
	require.Len(t, result.Files, 1)
	require.Equal(t, valid, result.Files[0].Metadata[dbfs.MetadataSharedRedirect])
	for _, invalid := range []string{expired, exhausted, deleted, recycled, delegated} {
		require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape(invalid), nil))
	}
	f.login(t)
	require.NoError(t, f.db.Share.UpdateOneID(id(expiredID)).ClearExpires().Exec(context.Background()))
	f.loginAs(t, recipient.Email, recipientPassword)
	require.Len(t, f.discoverPermissionShares(t, "", 50).Files, 2)
	require.NoError(t, f.db.User.UpdateOneID(2).SetStatus(entuser.StatusInactive).Exec(context.Background()))
	require.Empty(t, f.discoverPermissionShares(t, "", 50).Files)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/share/info/"+delegatedID, nil))
}

func TestFilePermissionsDiscoveryModePreservesManualShortcut(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/original/file.txt", []byte("shortcut"), nil)
	_, uri := f.createWritableShare(t, "cloudreve://my/original", map[string]any{"everyone": "IQ=="})
	recipient, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, recipient.Email, password)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"type": "folder", "uri": "cloudreve://my/saved-shortcut", "metadata": map[string]string{dbfs.MetadataSharedRedirect: uri, dbfs.MetadataSharedOwner: hashid.EncodeUserID(f.dep.HashIDEncoder(), 2)}}, nil)
	original := f.discoverPermissionShares(t, "", 20)
	require.Len(t, original.Files, 1)
	manualID := original.Files[0].ID
	require.False(t, strings.HasPrefix(manualID, "share:"))
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, recipient.Email, password)
	auto := f.discoverPermissionShares(t, "", 20)
	require.Len(t, auto.Files, 1)
	require.True(t, strings.HasPrefix(auto.Files[0].ID, "share:"))
	f.setPermissionDiscovery(t, false)
	f.loginAs(t, recipient.Email, password)
	restored := f.discoverPermissionShares(t, "", 20)
	require.Len(t, restored.Files, 1)
	require.Equal(t, manualID, restored.Files[0].ID)
	require.Equal(t, uri, restored.Files[0].Metadata[dbfs.MetadataSharedRedirect])
	require.Equal(t, []byte("shortcut"), f.readFile(t, uri+"/file.txt"))
}

func TestFilePermissionsDiscoverySortAndNameTypeSearch(t *testing.T) {
	f := newWritableShareFixture(t)
	for _, name := range []string{"zed", "alpha", "middle"} {
		f.upload(t, "cloudreve://my/sort/"+name+"/file.txt", []byte(name), nil)
		f.createWritableShare(t, "cloudreve://my/sort/"+name, map[string]any{"everyone": "IQ=="})
	}
	sourceID, err := f.dep.HashIDEncoder().Decode(f.fileInfo(t, "cloudreve://my/sort/zed").ID, hashid.FileID)
	require.NoError(t, err)
	oldest, err := f.db.Share.Create().SetUserID(2).SetFileID(sourceID).SetCreatedAt(time.Now().Add(-24 * time.Hour)).SetProps(&types.ShareProps{Permissions: &types.PermissionSetting{Everyone: types.ReadOnlyPermissions()}}).Save(context.Background())
	require.NoError(t, err)
	f.createWritableShare(t, "cloudreve://my/sort/alpha", map[string]any{"everyone": "AA=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.setPermissionDiscovery(t, true)
	f.loginAs(t, visitor.Email, password)
	list := func(uri, order, direction, token string, size int) explorer.ListResponse {
		q := url.Values{"uri": {uri}, "order_by": {order}, "order_direction": {direction}, "page_size": {fmt.Sprint(size)}}
		if token != "" {
			q.Set("next_page_token", token)
		}
		var result explorer.ListResponse
		f.request(t, http.MethodGet, "/api/v4/file?"+q.Encode(), nil, &result)
		return result
	}
	names := []string{}
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 10; page++ {
		result := list("cloudreve://shared_with_me", "name", "asc", token, 1)
		for _, row := range result.Files {
			require.False(t, seen[row.ID])
			seen[row.ID] = true
			names = append(names, row.Name)
		}
		token = result.Pagination.NextPageToken
		if token == "" {
			break
		}
	}
	require.Equal(t, []string{"alpha", "middle", "zed", "zed"}, names)
	oldestPage := list("cloudreve://shared_with_me", "created_at", "asc", "", 1)
	require.Equal(t, "share:"+hashid.EncodeShareID(f.dep.HashIDEncoder(), oldest.ID), oldestPage.Files[0].ID, "created time order must not be replaced with ID order")
	named := list("cloudreve://shared_with_me?name=ALP&case_folding", "name", "desc", "", 10)
	require.Len(t, named.Files, 1)
	require.Equal(t, "alpha", named.Files[0].Name)
	onlyFiles := list("cloudreve://shared_with_me?type=0", "name", "asc", "", 10)
	require.Empty(t, onlyFiles.Files)
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://shared_with_me?size_gte=1"), nil))
	require.NotZero(t, f.responseCode(t, http.MethodGet, "/api/v4/file?uri=cloudreve://shared_with_me&order_by=size", nil))
}
