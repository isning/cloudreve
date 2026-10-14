package controllers_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) bindFolder(t *testing.T, uri string, index int) {
	t.Helper()
	f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": uri, "policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[index].ID)}, nil)
}

func TestStorageNearestBindingForExistingAndNewUnboundSubdirectories(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	old := []byte("old subtree content stays in A")
	f.upload(t, "cloudreve://my/parent/existing/old.txt", old, nil)
	f.bindFolder(t, "cloudreve://my/parent", 1)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	existing := f.upload(t, "cloudreve://my/parent/existing/new.txt", []byte("existing unbound inherits B"), nil)
	require.Equal(t, b, existing.StoragePolicy.ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/parent/new/deep", "type": "folder"}, nil)
	next := f.upload(t, "cloudreve://my/parent/new/deep/new.txt", []byte("new unbound chain inherits B"), nil)
	require.Equal(t, b, next.StoragePolicy.ID)
	f.bindFolder(t, "cloudreve://my/parent/new", 0)
	f.bindFolder(t, "cloudreve://my/parent", 0)
	f.bindFolder(t, "cloudreve://my/parent", 1)
	own := f.upload(t, "cloudreve://my/parent/new/deep/own.txt", []byte("nearest explicit child A survives parent changes"), nil)
	require.Equal(t, a, own.StoragePolicy.ID)
	require.Equal(t, old, f.readFile(t, "cloudreve://my/parent/existing/old.txt"))
}

func TestStorageFilePreferenceSurvivesParentBindingAndExplicitVersion(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	_, err := f.db.User.UpdateOneID(2).SetSettings(&types.UserSetting{VersionRetention: true, VersionRetentionMax: 10}).Save(context.Background())
	require.NoError(t, err)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	uri := "cloudreve://my/parent/version.txt"
	initial := []byte("initial version A")
	f.upload(t, uri, initial, nil)
	f.bindFolder(t, "cloudreve://my/parent", 1)
	version := func(data []byte, policy any, expected string) {
		t.Helper()
		body := map[string]any{"uri": uri, "size": len(data), "entity_type": "version"}
		if policy != nil {
			body["policy_id"] = policy
		}
		var session explorer.UploadSessionResponse
		f.request(t, http.MethodPut, "/api/v4/file/upload", body, &session)
		require.Equal(t, expected, session.StoragePolicy.ID)
		f.finishUpload(t, session, data)
	}
	version([]byte("automatic version A"), nil, a)
	version([]byte("explicit version B"), b, b)
	// A stricter parent destination must not reject this file's own automatic A.
	settings := *f.policies[1].Settings
	settings.FileType = []string{"bin"}
	_, err = f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetSettings(&settings).SetMaxSize(1).Save(context.Background())
	require.NoError(t, err)
	version([]byte("automatic after explicit still A"), nil, a)
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	require.Equal(t, a, info.ExtendedInfo.StoragePolicy.ID)
	require.Len(t, info.ExtendedInfo.Entities, 4)
	for _, entity := range info.ExtendedInfo.Entities {
		var links explorer.FileURLResponse
		f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}, "entity": entity.ID}, &links)
		_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
		if entity.StoragePolicy.ID == b {
			require.Equal(t, "explicit version B", string(data))
		}
		require.NotEmpty(t, data)
	}
	require.Equal(t, []byte("automatic after explicit still A"), f.readFile(t, uri))
}

func TestStorageRevokedNearestPreferenceFallsDirectlyToFirstGrant(t *testing.T) {
	f := newStorageFixture(t)
	template := f.policies[0]
	_, err := f.s3.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("cloudreve-test-c")})
	require.NoError(t, err)
	third, err := f.db.StoragePolicy.Create().SetName("Bucket C").SetType(template.Type).SetServer(template.Server).SetBucketName("cloudreve-test-c").SetIsPrivate(true).
		SetAccessKey(template.AccessKey).SetSecretKey(template.SecretKey).SetDirNameRule(template.DirNameRule).SetFileNameRule(template.FileNameRule).SetSettings(template.Settings).Save(context.Background())
	require.NoError(t, err)
	f.policies = append(f.policies, third)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID, third.ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/ancestor/nearest", "type": "folder"}, nil)
	f.bindFolder(t, "cloudreve://my/ancestor", 1)
	f.bindFolder(t, "cloudreve://my/ancestor/nearest", 2)
	c := hashid.EncodePolicyID(f.dep.HashIDEncoder(), third.ID)
	a := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID)
	old := []byte("original content under nearest C")
	uri := "cloudreve://my/ancestor/nearest/existing.txt"
	f.upload(t, uri, old, nil)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	require.Equal(t, old, f.readFile(t, uri))
	session := f.upload(t, "cloudreve://my/ancestor/nearest/new.txt", []byte("revoked nearest C falls to first A instead of ancestor B"), nil)
	require.Equal(t, a, session.StoragePolicy.ID)
	var version explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len("updated on A"), "entity_type": "version"}, &version)
	require.Equal(t, a, version.StoragePolicy.ID)
	f.finishUpload(t, version, []byte("updated on A"))
	require.NotZero(t, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/ancestor/nearest/explicit.txt", "size": 1, "policy_id": c}))
	require.Equal(t, []byte("updated on A"), f.readFile(t, uri))
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	require.Equal(t, c, info.ExtendedInfo.StoragePolicy.ID, "fallback never rewrites the stored file preference")
	for _, index := range []int{1} {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(f.policies[index].BucketName)})
		require.NoError(t, err)
		require.Empty(t, objects.Contents, "farther valid ancestor is not tried")
	}
}
