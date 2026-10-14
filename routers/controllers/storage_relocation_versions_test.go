package controllers_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationMigratesAllRetainedVersionsWithTargetNoop(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	_, err := f.s3.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("cloudreve-test-c")})
	require.NoError(t, err)
	p := f.policies[0]
	c, err := f.db.StoragePolicy.Create().SetName("Bucket C").SetType(p.Type).SetServer(p.Server).SetBucketName("cloudreve-test-c").SetIsPrivate(true).
		SetAccessKey(p.AccessKey).SetSecretKey(p.SecretKey).SetDirNameRule(p.DirNameRule).SetFileNameRule(p.FileNameRule).SetSettings(p.Settings).Save(context.Background())
	require.NoError(t, err)
	f.policies = append(f.policies, c)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID, c.ID)
	f.enableMigration(t, true)
	uri := "cloudreve://my/history.txt"
	contents := map[string][]byte{}
	models := map[int]*ent.Entity{}
	for i, data := range [][]byte{[]byte("retained A version"), []byte("retained B version"), []byte("current C version")} {
		if i == 0 {
			f.upload(t, uri, data, nil)
		} else {
			var session explorer.UploadSessionResponse
			f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data), "entity_type": "version", "policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[i].ID)}, &session)
			f.finishUpload(t, session, data)
		}
		info := f.fileInfo(t, uri)
		contents[info.PrimaryEntity] = data
		id, err := f.dep.HashIDEncoder().Decode(info.PrimaryEntity, hashid.EntityID)
		require.NoError(t, err)
		models[id], err = f.db.Entity.Get(context.Background(), id)
		require.NoError(t, err)
	}
	before := f.fileInfo(t, uri)
	require.Len(t, before.ExtendedInfo.Entities, 3)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	var alreadyTarget *ent.Entity
	for _, e := range models {
		if e.StoragePolicyEntities == f.policies[1].ID {
			alreadyTarget = e
		}
	}
	require.NotNil(t, alreadyTarget)
	metaBefore, err := f.s3.HeadObject(&s3.HeadObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(alreadyTarget.Source)})
	require.NoError(t, err)
	var accepted explorer.TaskResponse
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": b}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	after := f.fileInfo(t, uri)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
	require.Equal(t, before.Size, after.Size)
	require.Equal(t, before.CreatedAt, after.CreatedAt)
	require.Equal(t, before.UpdatedAt, after.UpdatedAt)
	require.Equal(t, before.ExtendedInfo.StoragePolicy.ID, after.ExtendedInfo.StoragePolicy.ID)
	require.Len(t, after.ExtendedInfo.Entities, 3)
	for _, e := range after.ExtendedInfo.Entities {
		require.Equal(t, b, e.StoragePolicy.ID)
		var links explorer.FileURLResponse
		f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}, "entity": e.ID}, &links)
		require.Len(t, links.Urls, 1)
		require.True(t, strings.Contains(links.Urls[0].Url, f.policies[1].BucketName))
		_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
		require.Equal(t, contents[e.ID], data)
		id, err := f.dep.HashIDEncoder().Decode(e.ID, hashid.EntityID)
		require.NoError(t, err)
		current, err := f.db.Entity.Get(context.Background(), id)
		require.NoError(t, err)
		require.Equal(t, models[id].CreatedAt, current.CreatedAt)
		require.Equal(t, models[id].UpdatedAt, current.UpdatedAt)
	}
	metaAfter, err := f.s3.HeadObject(&s3.HeadObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(alreadyTarget.Source)})
	require.NoError(t, err)
	require.Equal(t, metaBefore.ETag, metaAfter.ETag)
	require.Equal(t, metaBefore.LastModified, metaAfter.LastModified)
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.Equal(t, capacityBefore.Used, capacityAfter.Used)
	f.assertObjectCounts(t, 2, 3, 1)
	items, err := f.db.RelocationItem.Query().All(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 3)
	noops := 0
	for _, item := range items {
		if item.State == relocationitem.StateNoop {
			noops++
		} else {
			require.Equal(t, relocationitem.StateCommitted, item.State)
		}
	}
	require.Equal(t, 1, noops)
	count, err := f.db.RelocationAttempt.Query().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, count)
}
