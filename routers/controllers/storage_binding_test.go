package controllers_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageFolderBindingChangesFutureWritesWithoutMovingExistingContent(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	old := []byte("file created before binding remains in A")
	f.upload(t, "cloudreve://my/bound/old.txt", old, nil)
	var before explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/bound/old.txt"), nil, &before)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/bound", "policy_id": b}, nil)
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(old), capacity.Used)
	require.Equal(t, old, f.readFile(t, "cloudreve://my/bound/old.txt"))
	var after explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/bound/old.txt"), nil, &after)
	require.Equal(t, before.ExtendedInfo.Entities, after.ExtendedInfo.Entities)
	session := f.upload(t, "cloudreve://my/bound/new.txt", []byte("automatic write into bound B"), nil)
	require.Equal(t, b, session.StoragePolicy.ID)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/bound"), nil, &listing)
	require.Equal(t, b, listing.StoragePolicy.ID)
	require.True(t, listing.Props.Capability.Enabled(21))
}

func TestStorageFolderBindingRejectsUnsupportedTargetsAndMissingPolicy(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	f.upload(t, "cloudreve://my/bound/file.txt", []byte("existing"), nil)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	for _, policy := range []any{nil, ""} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/bound", "policy_id": policy}))
	}
	require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/bound"}))
	foreign := hashid.EncodeUserID(f.dep.HashIDEncoder(), 1)
	for _, uri := range []string{"cloudreve://my/", "cloudreve://my/bound/file.txt", "cloudreve://trash/bound", "cloudreve://share/unknown", "cloudreve://" + foreign + "@my/bound", "cloudreve://my/missing"} {
		require.NotZero(t, f.responseCode(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": uri, "policy_id": b}))
	}
	session := f.upload(t, "cloudreve://my/bound/after-reject.txt", []byte("failed bind preserved automatic A"), nil)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), session.StoragePolicy.ID)
}
