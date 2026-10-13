package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageExplicitSecondPolicyUsesItsOwnRestrictionsAndLocation(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	settings := *f.policies[0].Settings
	settings.FileType = []string{"bin"}
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetMaxSize(1).SetSettings(&settings).Save(context.Background())
	require.NoError(t, err)
	uri := "cloudreve://my/explicit.txt"
	payload := []byte("selected B has no restrictive size or suffix from default A")
	id := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	session := f.upload(t, uri, payload, id)
	require.Equal(t, id, session.StoragePolicy.ID)
	require.Equal(t, payload, f.readFile(t, uri))
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	require.Equal(t, id, info.ExtendedInfo.StoragePolicy.ID)
	require.Len(t, info.ExtendedInfo.Entities, 1)
	require.Equal(t, id, info.ExtendedInfo.Entities[0].StoragePolicy.ID)
	for index, policy := range f.policies {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
		require.NoError(t, err)
		if index == 1 {
			require.Len(t, objects.Contents, 1)
		} else {
			require.Empty(t, objects.Contents)
		}
	}
}

func TestStorageUnauthorizedUploadsLeaveNoObjectsPlaceholdersOrQuota(t *testing.T) {
	f := newStorageFixture(t)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.Empty(t, listing.Files)
	for _, id := range []any{"invalid!", hashid.EncodePolicyID(f.dep.HashIDEncoder(), 999999), hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)} {
		body := map[string]any{"uri": "cloudreve://my/retry.txt", "size": 5, "policy_id": id, "import": true, "import_from": "forged", "thumbnail": true, "bypass": true}
		w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/file/upload", body, nil, f.token)
		var result struct {
			Code int `json:"code"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		require.NotZero(t, result.Code)
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
		require.Empty(t, listing.Files)
		var capacity fs.Capacity
		f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
		require.Zero(t, capacity.Used)
		for _, policy := range f.policies {
			objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
			require.NoError(t, err)
			require.Empty(t, objects.Contents)
		}
	}
	w := openIDRequest(t, f.router, http.MethodPost, "/api/v4/workflow/import", map[string]any{"policy_id": f.policies[1].ID}, nil, f.token)
	var forbidden struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &forbidden))
	require.Equal(t, serializer.CodeNoPermissionErr, forbidden.Code)
	f.upload(t, "cloudreve://my/retry.txt", []byte("valid retry uses the same path without retained lock"), hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID))
}

func TestStorageAutomaticUploadOmittedNullAndEmptyUseCurrentDefault(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[1].ID, f.policies[0].ID)
	for i, selection := range []any{nil, "", storageNullPolicy{}} {
		var id any = selection
		if _, ok := selection.(storageNullPolicy); ok {
			id = json.RawMessage("null")
		}
		uri := fmt.Sprintf("cloudreve://my/automatic-%d.txt", i)
		session := f.upload(t, uri, []byte("automatic selection contract"), id)
		require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), session.StoragePolicy.ID)
	}
	// No grants and no legacy default cannot select an arbitrary existing bucket.
	_, err := f.db.GroupPolicy.Delete().Where(grouppolicy.GroupID(2)).Exec(context.Background())
	require.NoError(t, err)
	_, err = f.db.Group.UpdateOneID(2).ClearStoragePolicies().Save(context.Background())
	require.NoError(t, err)
	var available []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &available)
	require.Empty(t, available)
	var before fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &before)
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/forbidden.txt", "size": 10}, nil, f.token)
	var rejected struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rejected))
	require.NotZero(t, rejected.Code)
	var after fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &after)
	require.Equal(t, before.Used, after.Used)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.Len(t, listing.Files, 3)
}

type storageNullPolicy struct{}
