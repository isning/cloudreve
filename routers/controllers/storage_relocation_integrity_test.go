package controllers_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationRejectsTruncatedAndCorruptBytes(t *testing.T) {
	for _, fault := range []string{"source_eof", "target_short", "target_corrupt_multipart"} {
		t.Run(fault, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			token := f.token
			f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			group := f.groupDetail(t)
			group["max_storage"] = 32 << 20
			f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
			f.token = token
			data := bytes.Repeat([]byte("integrity checked raw bytes\n"), 4096)
			if fault == "target_corrupt_multipart" {
				data = bytes.Repeat([]byte("multipart integrity\n"), 350000)
			}
			uri := "cloudreve://my/integrity.txt"
			f.upload(t, uri, data, nil)
			before := f.fileInfo(t, uri)
			var capacityBefore fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
			entityID, err := f.dep.HashIDEncoder().Decode(before.ExtendedInfo.Entities[0].ID, hashid.EntityID)
			require.NoError(t, err)
			original, err := f.db.Entity.Get(context.Background(), entityID)
			require.NoError(t, err)
			if fault == "target_corrupt_multipart" {
				meta, err := f.s3.HeadObject(&s3.HeadObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String(original.Source)})
				require.NoError(t, err)
				require.Contains(t, aws.StringValue(meta.ETag), "-", "source must actually have a multipart ETag")
			}
			index := 1
			if fault == "source_eof" {
				index = 0
			}
			backend, err := url.Parse(f.policies[index].Server)
			require.NoError(t, err)
			proxy := httputil.NewSingleHostReverseProxy(backend)
			var enabled, mutated atomic.Bool
			enabled.Store(true)
			proxy.ModifyResponse = func(res *http.Response) error {
				if !enabled.Load() || (res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent) {
					return nil
				}
				if fault == "source_eof" && res.Request.Method == http.MethodGet && strings.HasSuffix(res.Request.URL.Path, original.Source) {
					body, err := io.ReadAll(res.Body)
					res.Body.Close()
					if err != nil {
						return err
					}
					res.Body = io.NopCloser(bytes.NewReader(body[:len(body)/2]))
					// Keep the provider's original Content-Length to cause actual EOF.
					mutated.Store(true)
				}
				isComplete := (res.Request.Method == http.MethodPut && res.Request.URL.Query().Get("uploadId") == "") || (res.Request.Method == http.MethodPost && res.Request.URL.Query().Get("uploadId") != "")
				if fault != "source_eof" && isComplete && strings.Contains(res.Request.URL.Path, "/.cloudreve-relocation/") && !mutated.Swap(true) {
					key := strings.TrimPrefix(res.Request.URL.Path, "/"+f.policies[1].BucketName+"/")
					object, err := f.s3.GetObject(&s3.GetObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(key)})
					if err != nil {
						return err
					}
					body, err := io.ReadAll(object.Body)
					object.Body.Close()
					if err != nil {
						return err
					}
					if fault == "target_short" {
						body = body[:len(body)/2]
					} else {
						body[len(body)-1] ^= 0xff
					}
					_, err = f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[1].BucketName), Key: aws.String(key), Body: bytes.NewReader(body)})
					return err
				}
				return nil
			}
			server := httptest.NewServer(proxy)
			t.Cleanup(server.Close)
			_, err = f.db.StoragePolicy.UpdateOneID(f.policies[index].ID).SetServer(server.URL).Save(context.Background())
			require.NoError(t, err)
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			failed := f.waitForStorageTask(t, accepted.ID, "error")
			enabled.Store(false)
			require.True(t, mutated.Load(), "real provider fault must have executed")
			require.NotContains(t, failed.Error, f.policies[0].AccessKey)
			require.NotContains(t, failed.Error, f.policies[0].SecretKey)
			require.NotContains(t, failed.Error, "X-Amz-")
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.ExtendedInfo.Entities[0].ID, after.ExtendedInfo.Entities[0].ID)
			require.Equal(t, before.ExtendedInfo.Entities[0].StoragePolicy.ID, after.ExtendedInfo.Entities[0].StoragePolicy.ID)
			require.True(t, bytes.Equal(data, f.readFile(t, uri)))
			var capacityAfter fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
			require.Equal(t, capacityBefore.Used, capacityAfter.Used)
			item, err := f.db.RelocationItem.Query().Only(context.Background())
			require.NoError(t, err)
			require.Equal(t, relocationitem.StateFailed, item.State)
			attempt, err := item.QueryAttempts().Only(context.Background())
			require.NoError(t, err)
			require.False(t, attempt.Verified)
			require.NotEmpty(t, attempt.TargetKey)
			require.Equal(t, relocationattempt.CleanupPending, attempt.Cleanup)
		})
	}
}
