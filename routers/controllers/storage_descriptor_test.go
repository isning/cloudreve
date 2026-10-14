package controllers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStoragePublicDescriptorsExposeRestrictionsWithoutPrivateConfiguration(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	private := storageRandom(t)
	settings := *f.policies[1].Settings
	settings.Token = private
	settings.FileType = []string{"txt"}
	settings.NameRegexp = ".*\\.txt$"
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetSettings(&settings).SetMaxSize(1024).Save(context.Background())
	require.NoError(t, err)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, f.policies[1].Name, policies[1].Name)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), policies[1].ID)
	require.EqualValues(t, 1024, policies[1].MaxSize)
	require.Equal(t, []string{"txt"}, policies[1].AllowedSuffix)
	require.Equal(t, ".*\\.txt$", policies[1].AllowedNameRegexp)
	session := f.upload(t, "cloudreve://my/descriptor.txt", []byte("reduced descriptor"), policies[1].ID)
	for _, descriptor := range []any{policies, session.StoragePolicy} {
		raw, err := json.Marshal(descriptor)
		require.NoError(t, err)
		for _, value := range []string{private, f.policies[1].AccessKey, f.policies[1].SecretKey, f.policies[1].Server} {
			require.NotContains(t, string(raw), value)
		}
		for _, field := range []string{"access_key", "secret_key", "settings", "server", "bucket_name", "node_id"} {
			require.NotContains(t, string(raw), `"`+field+`"`)
		}
	}
	require.Equal(t, policies[1], *session.StoragePolicy)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1, "other account queries only its current group grants")
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), policies[0].ID)
	f.token = ""
	require.Equal(t, serializer.CodeCheckLogin, f.responseCode(t, http.MethodGet, "/api/v4/user/setting/policies", nil))
}
