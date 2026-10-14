package controllers_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) assertObjectCounts(t *testing.T, counts ...int) {
	t.Helper()
	for i, count := range counts {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(f.policies[i].BucketName)})
		require.NoError(t, err)
		require.Len(t, objects.Contents, count)
	}
}

func (f *storageFixture) enableArchive(t *testing.T) {
	t.Helper()
	token := f.token
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	bs, err := boolset.FromString(group["permissions"].(string))
	require.NoError(t, err)
	boolset.Set(int(types.GroupPermissionArchiveTask), true, bs)
	group["permissions"] = bs
	group["settings"] = &types.GroupSetting{MaxWalkedFiles: 10000, CompressSize: 1 << 20, DecompressSize: 1 << 20}
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.token = token
	// The fixture seeds an empty master to exercise startup upgrades. Enable the
	// pre-existing native archive capabilities, as on a real installation.
	master, err := f.db.Node.Get(context.Background(), 1)
	require.NoError(t, err)
	boolset.Set(int(types.NodeCapabilityCreateArchive), true, master.Capabilities)
	boolset.Set(int(types.NodeCapabilityExtractArchive), true, master.Capabilities)
	_, err = f.db.Node.UpdateOne(master).SetCapabilities(master.Capabilities).Save(context.Background())
	require.NoError(t, err)
	_, err = f.db.Setting.Create().SetName("queue_io_intense_max_retry").SetValue("0").Save(context.Background())
	require.NoError(t, err)
}

func storageZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range files {
		entry, err := w.Create(name)
		require.NoError(t, err)
		_, err = entry.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return b.Bytes()
}

func TestStorageArchiveOutputUsesBoundDestination(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableArchive(t)
	src, dst := "cloudreve://my/input.txt", "cloudreve://my/output/archive.zip"
	data := []byte("archive reads A and writes B")
	f.upload(t, src, data, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/output", "type": "folder"}, nil)
	f.bindFolder(t, "cloudreve://my/output", 1)
	before := f.fileInfo(t, src)
	var capacityBefore fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityBefore)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	info := f.fileInfo(t, dst)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), info.ExtendedInfo.Entities[0].StoragePolicy.ID)
	archive := f.readFile(t, dst)
	r, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)
	require.Len(t, r.File, 1)
	entry, err := r.File[0].Open()
	require.NoError(t, err)
	got, err := io.ReadAll(entry)
	require.NoError(t, err)
	require.NoError(t, entry.Close())
	require.Equal(t, data, got)
	require.Equal(t, before.ExtendedInfo.Entities, f.fileInfo(t, src).ExtendedInfo.Entities)
	require.Equal(t, data, f.readFile(t, src))
	var capacityAfter fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacityAfter)
	require.EqualValues(t, capacityBefore.Used+int64(len(archive)), capacityAfter.Used)
}

func TestStorageArchiveAndExtractRejectRevokedQueuedDestination(t *testing.T) {
	for _, kind := range []string{"archive", "extract"} {
		t.Run(kind, func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableArchive(t)
			src, dst := "cloudreve://my/input.zip", "cloudreve://my/output"
			f.upload(t, src, storageZip(t, map[string][]byte{"result.txt": []byte("queued before revoke")}), nil)
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": dst, "type": "folder"}, nil)
			f.bindFolder(t, dst, 1)
			if kind == "archive" {
				dst += "/result.zip"
			}
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/"+kind, map[string]any{"src": []string{src}, "dst": dst}, &accepted)
			f.assignPolicies(t, f.policies[0].ID)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.login(t)
			failed := f.waitForStorageTask(t, accepted.ID, "error")
			require.NotEmpty(t, failed.Error)
			f.assertObjectCounts(t, 2, 0) // includes the legacy fixture object
		})
	}
}

func TestStorageExtractOutputInheritsBoundDestination(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableArchive(t)
	src, dst := "cloudreve://my/input.zip", "cloudreve://my/output"
	files := map[string][]byte{"first.txt": []byte("first"), "nested/deep/second.txt": []byte("second")}
	archive := storageZip(t, files)
	f.upload(t, src, archive, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": dst, "type": "folder"}, nil)
	f.bindFolder(t, dst, 1)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/extract", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	for name, data := range files {
		uri := dst + "/" + name
		require.Equal(t, data, f.readFile(t, uri))
		require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), f.fileInfo(t, uri).ExtendedInfo.Entities[0].StoragePolicy.ID)
	}
	require.Nil(t, f.fileInfo(t, dst+"/nested").ExtendedInfo.StoragePolicy)
	require.Equal(t, archive, f.readFile(t, src))
	f.assertObjectCounts(t, 2, 2)
}

func TestStorageExtractEnforcesDestinationRestrictions(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableArchive(t)
	src, dst := "cloudreve://my/input.zip", "cloudreve://my/output"
	f.upload(t, src, storageZip(t, map[string][]byte{"result.txt": []byte("larger than destination limit")}), nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": dst, "type": "folder"}, nil)
	f.bindFolder(t, dst, 1)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/extract", map[string]any{"src": []string{src}, "dst": dst}, &accepted)
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetMaxSize(1).Save(context.Background())
	require.NoError(t, err)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	failed := f.waitForStorageTask(t, accepted.ID, "error")
	require.NotEmpty(t, failed.Error)
	f.assertObjectCounts(t, 2, 0)
}

func TestStorageArchiveProviderFailureDoesNotSwitchBuckets(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.enableArchive(t)
	src, folder := "cloudreve://my/input.txt", "cloudreve://my/output"
	f.upload(t, src, []byte("archive source remains readable"), nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
	f.bindFolder(t, folder, 1)
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{src}, "dst": folder + "/failed.zip"}, &accepted)
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[1].ID).SetServer("http://127.0.0.1:1").Save(context.Background())
	require.NoError(t, err)
	w := launchStorageWorkerWithWorkflows(t, f)
	f.remote = w.ready(t)
	f.login(t)
	failed := f.waitForStorageTask(t, accepted.ID, "error")
	require.NotEmpty(t, failed.Error)
	f.assertObjectCounts(t, 2, 0)
	require.Equal(t, []byte("archive source remains readable"), f.readFile(t, src))
}
