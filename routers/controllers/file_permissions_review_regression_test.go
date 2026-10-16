package controllers_test

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/routers"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsDelegationFinalCheckRejectsRevokedSourceAndGroup(t *testing.T) {
	f := newWritableShareFixture(t)
	visitor, password := f.createWritableVisitor(t, 2)
	for _, revoke := range []string{"acl", "link", "anonymous_policy"} {
		f.login(t)
		base := "cloudreve://my/delegation-" + revoke
		name := "delegate-" + revoke + ".txt"
		f.upload(t, base+"/"+name, []byte("delegation source"), nil)
		id, share := f.createWritableShare(t, base, map[string]any{"everyone": "Pw==", "anonymous": "IQ=="})
		f.loginAs(t, visitor.Email, password)
		reached, resume := pausePermissionFileRead(t, f, name, "delegate-"+revoke)
		result := f.permissionAsyncRequest(t, http.MethodPut, "/api/v4/share", map[string]any{"uri": share + "/" + name, "permissions": map[string]string{"everyone": "Lw=="}}, "delegate-"+revoke)
		awaitPermissionPause(t, reached)
		f.login(t)
		group := f.db.Group.GetX(context.Background(), 2)
		switch revoke {
		case "acl":
			f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{base + "/" + name}, "setting": map[string]string{"everyone": "IQ=="}}, nil)
		case "link":
			f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
		case "anonymous_policy":
			p := append(boolset.BooleanSet{}, (*group.Permissions)...)
			boolset.Set(14, false, &p)
			require.NoError(t, f.db.Group.UpdateOne(group).SetPermissions(&p).Exec(context.Background()))
		}
		before := f.db.Share.Query().CountX(context.Background())
		resume()
		require.NotZero(t, awaitPermissionResult(t, result).Code)
		require.Equal(t, before, f.db.Share.Query().CountX(context.Background()))
		require.NoError(t, f.db.Group.UpdateOneID(2).SetPermissions(group.Permissions).Exec(context.Background()))
	}
}

type permissionSmallPages struct {
	inventory.FileClient
	pages *atomic.Int64
}

func (c *permissionSmallPages) SetClient(client *ent.Client) inventory.TxOperator {
	return &permissionSmallPages{FileClient: c.FileClient.SetClient(client).(inventory.FileClient), pages: c.pages}
}
func (c *permissionSmallPages) GetChildFiles(ctx context.Context, args *inventory.ListFileParameters, owner int, roots ...*ent.File) (*inventory.ListFileResult, error) {
	copyArgs := *args
	page := *args.PaginationArgs
	copyArgs.PaginationArgs = &page
	if page.UseCursorPagination {
		page.PageSize = min(page.PageSize, 2)
		if page.PageToken != "" {
			c.pages.Add(1)
		}
	}
	return c.FileClient.GetChildFiles(ctx, &copyArgs, owner, roots...)
}

func TestFilePermissionsRecursiveAuthorizationChecksLaterPages(t *testing.T) {
	f := newWritableShareFixture(t)
	for i := 0; i < 6; i++ {
		f.upload(t, fmt.Sprintf("cloudreve://my/pages/source/f%d.txt", i), []byte("paged bytes"), nil)
	}
	f.upload(t, "cloudreve://my/pages/destination/seed.txt", []byte("seed"), nil)
	_, share := f.createWritableShare(t, "cloudreve://my/pages", map[string]any{"everyone": "Lw=="})
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/pages/source/f5.txt"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	visitor, password := f.createWritableVisitor(t, 2)
	var pages atomic.Int64
	d := dependency.NewDependency(dependency.WithDbClient(f.db), dependency.WithConfigProvider(f.dep.ConfigProvider()), dependency.WithLogger(f.dep.Logger()), dependency.WithKV(f.dep.KV()), dependency.WithHashIDEncoder(f.dep.HashIDEncoder()), dependency.WithSettingProvider(f.dep.SettingProvider()), dependency.WithFileClient(&permissionSmallPages{FileClient: f.dep.FileClient(), pages: &pages}))
	t.Cleanup(func() { d.Shutdown(context.Background()) })
	f.dep = d
	f.router = routers.InitRouter(d)
	f.loginAs(t, visitor.Email, password)
	require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{share + "/source"}, "dst": share + "/destination", "copy": true}))
	require.GreaterOrEqual(t, pages.Load(), int64(2), "complete traversal must advance beyond the first two pages")
	f.login(t)
	require.Equal(t, []byte("paged bytes"), f.readFile(t, "cloudreve://my/pages/source/f5.txt"))
	f.request(t, http.MethodDelete, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/pages/source/f5.txt"}}, nil)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{share + "/source"}, "dst": share + "/destination", "copy": true}, nil)
	f.login(t)
	require.Equal(t, []byte("paged bytes"), f.readFile(t, "cloudreve://my/pages/destination/source/f5.txt"))
}

func TestFilePermissionsShareTransactionDoesNotRequireAuditContext(t *testing.T) {
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/internal-share.txt", []byte("internal share"), nil)
	u, err := f.dep.UserClient().GetLoginUserByID(context.Background(), 2)
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), inventory.UserCtx{}, u)
	m := manager.NewFileManager(f.dep, u)
	defer m.Recycle()
	uri, err := fs.NewUriFromString("cloudreve://my/internal-share.txt")
	require.NoError(t, err)
	share, err := m.CreateOrUpdateShare(ctx, uri, &manager.CreateShareArgs{})
	require.NoError(t, err)
	require.Positive(t, share.ID)
}
