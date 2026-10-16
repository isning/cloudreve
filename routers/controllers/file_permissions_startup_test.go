package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/stretchr/testify/require"
)

func TestFilePermissionsExistingInstallationRestartsWithoutRewritingACL(t *testing.T) {
	t.Setenv("CLOUDREVE_PERMISSION_FULL_ROUTER", "1")
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/existing/zero.txt", []byte("preserved zero"), nil)
	f.upload(t, "cloudreve://my/existing/empty.txt", []byte("preserved empty"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/existing/zero.txt"}, "setting": map[string]string{"everyone": "AA=="}}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{"uris": []string{"cloudreve://my/existing/empty.txt"}, "setting": map[string]string{}}, nil)
	_, share := f.createWritableShare(t, "cloudreve://my/existing", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"type": "folder", "uri": "cloudreve://my/saved-shortcut", "metadata": map[string]string{dbfs.MetadataSharedRedirect: share, dbfs.MetadataSharedOwner: hashid.EncodeUserID(f.dep.HashIDEncoder(), 2)}}, nil)
	manual := f.discoverPermissionShares(t, "", 20).Files[0].ID
	_, err := f.db.Setting.Delete().Where(setting.Name("shared_with_me_acl")).Exec(context.Background())
	require.NoError(t, err)
	markers, err := f.db.Setting.Query().Where(setting.NameHasPrefix(inventory.DBVersionPrefix)).All(context.Background())
	require.NoError(t, err)
	markerValues := map[string]string{}
	for _, marker := range markers {
		markerValues[marker.Name] = marker.Value
	}
	for i := 0; i < 2; i++ {
		worker := launchStorageWorker(t, f)
		f.remote = worker.ready(t)
		f.loginAs(t, visitor.Email, password)
		var config struct {
			Enabled bool `json:"shared_with_me_acl"`
		}
		f.request(t, http.MethodGet, "/api/v4/site/config/explorer", nil, &config)
		require.Equal(t, i == 1, config.Enabled)
		if i == 0 {
			require.Equal(t, manual, f.discoverPermissionShares(t, "", 20).Files[0].ID)
		}
		require.NotZero(t, f.responseCode(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{share + "/zero.txt"}}))
		require.Equal(t, []byte("preserved empty"), f.readFile(t, share+"/empty.txt"))
		f.login(t)
		zero, err := json.Marshal(f.permissionInfo(t, "cloudreve://my/existing/zero.txt").ExtendedInfo.Permissions)
		require.NoError(t, err)
		require.JSONEq(t, `{"everyone":"AA=="}`, string(zero))
		empty, err := json.Marshal(f.permissionInfo(t, "cloudreve://my/existing/empty.txt").ExtendedInfo.Permissions)
		require.NoError(t, err)
		require.JSONEq(t, `{}`, string(empty))
		f.setPermissionDiscovery(t, true)
		worker.stop(t)
		f.remote = ""
	}
	for key, value := range markerValues {
		marker, err := f.db.Setting.Query().Where(setting.Name(key)).Only(context.Background())
		require.NoError(t, err)
		require.Equal(t, value, marker.Value)
	}
	f.setPermissionDiscovery(t, false)
	f.loginAs(t, visitor.Email, password)
	require.Equal(t, manual, f.discoverPermissionShares(t, "", 20).Files[0].ID)
}
