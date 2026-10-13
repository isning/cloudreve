package controllers_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func TestStorageActiveUploadProtectsPhysicalPolicyConfiguration(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	uri := "cloudreve://my/protected.txt"
	data := []byte("pending multipart location cannot be retargeted by admin")
	var session explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data), "policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &session)
	worker := launchStorageWorker(t, f)
	adminWorker := worker.ready(t)
	f.remote = adminWorker
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	endpoint := fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID)
	var original ent.StoragePolicy
	f.request(t, http.MethodGet, endpoint, nil, &original)
	for _, mutate := range []func(*ent.StoragePolicy){
		func(p *ent.StoragePolicy) { p.BucketName = "different-bucket" },
		func(p *ent.StoragePolicy) { p.Type = "local" },
		func(p *ent.StoragePolicy) { p.NodeID = 999999 },
		func(p *ent.StoragePolicy) { p.Server = "http://127.0.0.1:1" },
		func(p *ent.StoragePolicy) {
			s := *p.Settings
			s.ServerSideEndpoint = "http://127.0.0.1:1"
			p.Settings = &s
		},
	} {
		next := original
		mutate(&next)
		require.NotZero(t, f.responseCode(t, http.MethodPut, endpoint, map[string]any{"policy": next}), "physical edit must be rejected")
		var stored ent.StoragePolicy
		f.request(t, http.MethodGet, endpoint, nil, &stored)
		require.Equal(t, original.Type, stored.Type)
		require.Equal(t, original.Server, stored.Server)
		require.Equal(t, original.BucketName, stored.BucketName)
		require.Equal(t, original.Settings.ServerSideEndpoint, stored.Settings.ServerSideEndpoint)
	}
	require.NotZero(t, f.responseCode(t, http.MethodDelete, endpoint, nil))
	// A name/settings change and credential save at the same locator remain valid.
	next := original
	next.Name = "Renamed while uploading"
	f.request(t, http.MethodPut, endpoint, map[string]any{"policy": next}, nil)
	next.SecretKey = storageRandom(t)
	f.request(t, http.MethodPut, endpoint, map[string]any{"policy": next}, nil)
	var rotated ent.StoragePolicy
	f.request(t, http.MethodGet, endpoint, nil, &rotated)
	require.Equal(t, next.SecretKey, rotated.SecretKey, "credential saves do not change the physical locator")
	f.request(t, http.MethodPut, endpoint, map[string]any{"policy": original}, nil)
	f.remote = ""
	f.login(t)
	f.finishUpload(t, session, data)
	require.Equal(t, data, f.readFile(t, uri))
	f.remote = adminWorker
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	// Once the session completes, unrelated physical edits are no longer blocked
	// by this active-upload guard. Restore before checking the original content.
	next.Server = "http://127.0.0.1:1"
	f.request(t, http.MethodPut, endpoint, map[string]any{"policy": next}, nil)
	f.request(t, http.MethodPut, endpoint, map[string]any{"policy": original}, nil)
	f.remote = ""
	f.login(t)
	require.Equal(t, data, f.readFile(t, uri))
}
