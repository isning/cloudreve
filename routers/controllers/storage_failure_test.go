package controllers_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/pkg/conf"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageChosenAndBoundProviderFailuresNeverSwitchBuckets(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/bound", "type": "folder"}, nil)
	f.bindFolder(t, "cloudreve://my/bound", 1)
	original := f.policies[1].Server
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer("http://127.0.0.1:1").Save(context.Background())
	require.NoError(t, err)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	for _, selection := range []any{b, nil} {
		body := map[string]any{"uri": "cloudreve://my/bound/retry.txt", "size": 7}
		if selection != nil {
			body["policy_id"] = selection
		}
		result := f.responseResult(t, http.MethodPut, "/api/v4/file/upload", body)
		require.NotZero(t, result.Code)
		require.NotEmpty(t, result.Msg)
		require.NotContains(t, result.Msg, f.policies[1].SecretKey)
		require.NotContains(t, result.Msg, f.policies[1].AccessKey)
		var capacity fs.Capacity
		f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
		require.Zero(t, capacity.Used)
		var listing explorer.ListResponse
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/bound"), nil, &listing)
		require.Empty(t, listing.Files)
		for _, policy := range f.policies {
			objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
			require.NoError(t, err)
			require.Empty(t, objects.Contents)
		}
	}
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer(original).Save(context.Background())
	require.NoError(t, err)
	data := []byte("same destination works after provider recovery")
	session := f.upload(t, "cloudreve://my/bound/retry.txt", data, nil)
	require.Equal(t, b, session.StoragePolicy.ID)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/bound/retry.txt"))
}

func TestStoragePolicyRowDecodingFailureNeverFallsBackToHealthyBucket(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/bound", "type": "folder"}, nil)
	f.bindFolder(t, "cloudreve://my/bound", 1)
	driver := string(f.database.Type)
	if driver == "" || driver == string(conf.SQLiteDB) {
		driver = "sqlite3"
	}
	if driver == string(conf.MariaDB) {
		driver = "mysql"
	}
	dsn := f.database.DatabaseURL
	if dsn == "" {
		dsn = f.database.DBFile
	}
	rawDB, err := sql.Open(driver, dsn)
	require.True(t, err == nil, "owned SQL fixture connection failed")
	t.Cleanup(func() { require.NoError(t, rawDB.Close()) })
	update := "UPDATE storage_policies SET settings = ? WHERE id = ?"
	if driver == "postgres" {
		update = "UPDATE storage_policies SET settings = $1 WHERE id = $2"
	}
	// A valid JSON scalar passes DB JSON validation on every supported dialect
	// but fails the actual Ent row decoder for a structured PolicySetting.
	_, err = rawDB.ExecContext(context.Background(), update, `"storage-row-decoder-fixture"`, f.policies[1].ID)
	require.NoError(t, err)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	for _, selection := range []any{b, nil} {
		body := map[string]any{"uri": "cloudreve://my/bound/decoder-retry.txt", "size": 3}
		if selection != nil {
			body["policy_id"] = selection
		}
		result := f.responseResult(t, http.MethodPut, "/api/v4/file/upload", body)
		require.NotZero(t, result.Code)
		require.NotEmpty(t, result.Msg)
		require.NotContains(t, result.Msg, f.policies[1].SecretKey)
		require.NotContains(t, result.Msg, f.policies[1].AccessKey)
		var capacity fs.Capacity
		f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
		require.Zero(t, capacity.Used)
		for _, policy := range f.policies {
			objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
			require.NoError(t, err)
			require.Empty(t, objects.Contents)
		}
	}
	restored, err := json.Marshal(f.policies[1].Settings)
	require.NoError(t, err)
	_, err = rawDB.ExecContext(context.Background(), update, string(restored), f.policies[1].ID)
	require.NoError(t, err)
	session := f.upload(t, "cloudreve://my/bound/decoder-retry.txt", []byte("row decoder recovery"), nil)
	require.Equal(t, b, session.StoragePolicy.ID)
}
