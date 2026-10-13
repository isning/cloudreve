package controllers_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageRelocationPreservesRawBytesAcrossOppositeEncryptionDefaults(t *testing.T) {
	for _, encrypted := range []bool{true, false} {
		name := "plain_to_encrypted_default"
		if encrypted {
			name = "encrypted_to_plain_default"
		}
		t.Run(name, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			for i, p := range f.policies {
				settings := *p.Settings
				settings.Encryption = encrypted
				if i == 1 {
					settings.Encryption = !encrypted
				}
				_, err := f.db.StoragePolicy.UpdateOne(p).SetSettings(&settings).Save(context.Background())
				require.NoError(t, err)
			}
			server := httptest.NewServer(f.router)
			t.Cleanup(server.Close)
			_, err := f.db.Setting.Update().Where(setting.Name("siteURL")).SetValue(server.URL).Save(context.Background())
			require.NoError(t, err)
			uri := "cloudreve://my/encryption.txt"
			data := []byte("only original stored bytes and encryption metadata may migrate")
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "file"}, nil)
			w := f.binaryRequest(t, http.MethodPut, "/api/v4/file/content?uri="+url.QueryEscape(uri), data, "", "")
			var result struct{ Code int }
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
			require.Zero(t, result.Code)
			before := f.fileInfo(t, uri)
			require.Len(t, before.ExtendedInfo.Entities, 1)
			id, err := f.dep.HashIDEncoder().Decode(before.ExtendedInfo.Entities[0].ID, hashid.EntityID)
			require.NoError(t, err)
			original, err := f.db.Entity.Get(context.Background(), id)
			require.NoError(t, err)
			require.Equal(t, encrypted, original.Props != nil && original.Props.EncryptMetadata != nil)
			raw := func(bucket, key string) []byte {
				t.Helper()
				object, err := f.s3.GetObject(&s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
				require.NoError(t, err)
				defer object.Body.Close()
				body, err := io.ReadAll(object.Body)
				require.NoError(t, err)
				return body
			}
			rawBefore := raw(f.policies[0].BucketName, original.Source)
			require.Equal(t, encrypted, !bytes.Equal(data, rawBefore))
			var capacityBefore fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			worker := launchStorageWorkerWithWorkflows(t, f)
			f.remote = worker.ready(t)
			f.login(t)
			f.waitForStorageTask(t, accepted.ID, "completed")
			current, err := f.db.Entity.Get(context.Background(), id)
			require.NoError(t, err)
			rawAfter := raw(f.policies[1].BucketName, current.Source)
			require.Equal(t, sha256.Sum256(rawBefore), sha256.Sum256(rawAfter))
			originalProps, err := json.Marshal(original.Props)
			require.NoError(t, err)
			currentProps, err := json.Marshal(current.Props)
			require.NoError(t, err)
			require.True(t, bytes.Equal(originalProps, currentProps), "private encryption metadata is preserved exactly")
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
			require.Len(t, after.ExtendedInfo.Entities, 1)
			require.True(t, bytes.Equal(data, f.readFile(t, uri)), "native signed HTTP content returns the original cleartext")
			var capacityAfter fs.Capacity
			f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
			require.Equal(t, capacityBefore.Used, capacityAfter.Used)
		})
	}
}
