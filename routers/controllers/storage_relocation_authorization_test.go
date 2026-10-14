package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/stretchr/testify/require"
)

func authenticateStorageMigration(t *testing.T, f *storageFixture, external bool) {
	t.Helper()
	if !external {
		f.login(t)
		return
	}
	if f.remote == "" {
		server := httptest.NewServer(f.router)
		defer server.Close()
		f.remote = server.URL
		defer func() { f.remote = "" }()
	}
	f.oidcLogin(t)
}

func TestStorageRelocationCanReadRevokedSourceAndKeepsCommittedTarget(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "oidc"}[external], func(t *testing.T) {
			f := newStorageFixtureWithLegacy(t, true)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.enableMigration(t, true)
			authenticateStorageMigration(t, f, external)
			originalToken := f.token
			uri := "cloudreve://my/revoked-source.txt"
			data := []byte("old source is readable even without new-write authorization")
			f.upload(t, uri, data, nil)
			before := f.fileInfo(t, uri)
			f.assignPolicies(t, f.policies[1].ID)
			f.token = originalToken
			require.Equal(t, data, f.readFile(t, uri))
			var accepted explorer.TaskResponse
			f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
			w := launchStorageWorkerWithWorkflows(t, f)
			f.remote = w.ready(t)
			f.token = originalToken
			f.waitForStorageTask(t, accepted.ID, "completed")
			f.assignPolicies(t, f.policies[0].ID)
			f.token = originalToken
			require.Equal(t, data, f.readFile(t, uri))
			after := f.fileInfo(t, uri)
			require.Equal(t, before.ID, after.ID)
			require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), after.ExtendedInfo.Entities[0].StoragePolicy.ID)
			f.waitForStorageTask(t, accepted.ID, "completed")
		})
	}
}

func TestStorageRelocationRechecksDestinationAfterPlanAndPut(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "oidc"}[external], func(t *testing.T) {
			for _, boundary := range []relocationitem.State{relocationitem.StatePlanned, relocationitem.StateVerified} {
				t.Run(string(boundary), func(t *testing.T) {
					f := newStorageFixtureWithLegacy(t, true)
					f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
					f.enableMigration(t, true)
					authenticateStorageMigration(t, f, external)
					originalToken := f.token
					uri := "cloudreve://my/revoked-target.txt"
					data := []byte("uncommitted content must not follow a revoked destination")
					f.upload(t, uri, data, nil)
					before := f.fileInfo(t, uri)
					var accepted explorer.TaskResponse
					f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": []string{uri}, "dst_policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)}, &accepted)
					w := launchStorageWorkerWithWorkflows(t, f)
					_ = w.ready(t)
					f.waitForRelocationItem(t, accepted.ID, boundary)
					// Revoke from the issuing process so the running worker retains
					// its old Task owner and any old navigation state.
					f.assignPolicies(t, f.policies[0].ID)
					f.remote = w.ready(t)
					f.token = originalToken
					f.waitForStorageTask(t, accepted.ID, "error")
					after := f.fileInfo(t, uri)
					require.Equal(t, before.ID, after.ID)
					require.Equal(t, before.PrimaryEntity, after.PrimaryEntity)
					require.Equal(t, before.ExtendedInfo.Entities[0].StoragePolicy.ID, after.ExtendedInfo.Entities[0].StoragePolicy.ID)
					require.Equal(t, data, f.readFile(t, uri))
					if boundary == relocationitem.StatePlanned {
						f.assertObjectCounts(t, 2, 0)
					} else {
						f.assertObjectCounts(t, 2, 1)
					}
				})
			}
		})
	}
}
