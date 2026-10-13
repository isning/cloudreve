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

func (f *storageFixture) groupDetail(t *testing.T) map[string]any {
	t.Helper()
	var detail map[string]any
	f.request(t, http.MethodGet, "/api/v4/admin/group/2", nil, &detail)
	return detail["group"].(map[string]any)
}

func (f *storageFixture) assignPolicies(t *testing.T, ids ...int) {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	delete(group, "edges")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": ids}, nil)
	f.login(t)
}

func (f *storageFixture) readFile(t *testing.T, uri string) []byte {
	t.Helper()
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}}, &links)
	require.Len(t, links.Urls, 1)
	_, data := storageHTTP(t, http.MethodGet, links.Urls[0].Url, nil)
	return data
}

func TestStorageReorderedDefaultWritesWithoutMovingOldContent(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	first := []byte("before reorder remains in bucket A")
	f.upload(t, "cloudreve://my/before.txt", first, nil)
	var before explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/before.txt"), nil, &before)
	f.assignPolicies(t, f.policies[1].ID, f.policies[0].ID)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), policies[0].ID)
	next := []byte("after reorder goes to bucket B")
	session := f.upload(t, "cloudreve://my/after.txt", next, nil)
	require.Equal(t, policies[0].ID, session.StoragePolicy.ID)
	require.Equal(t, first, f.readFile(t, "cloudreve://my/before.txt"))
	require.Equal(t, next, f.readFile(t, "cloudreve://my/after.txt"))
	var after explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape("cloudreve://my/before.txt"), nil, &after)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.ExtendedInfo.Entities, after.ExtendedInfo.Entities)
	var capacity fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
	require.EqualValues(t, len(first)+len(next), capacity.Used)
	for _, policy := range f.policies {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
		require.NoError(t, err)
		require.Len(t, objects.Contents, 1)
	}
}

func (f *storageFixture) assertGroupPolicies(t *testing.T, ids ...int) {
	t.Helper()
	var detail struct {
		PolicyIDs []int `json:"policy_ids"`
		Group     struct {
			StoragePolicyID int `json:"storage_policy_id"`
		} `json:"group"`
	}
	f.request(t, http.MethodGet, "/api/v4/admin/group/2", nil, &detail)
	require.Equal(t, ids, detail.PolicyIDs)
	require.Equal(t, ids[0], detail.Group.StoragePolicyID)
}

func (f *storageFixture) rejectGroupUpdate(t *testing.T, body any) {
	t.Helper()
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/admin/group/2", body, nil, f.token)
	var envelope struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	require.Equal(t, serializer.CodeParamErr, envelope.Code)
}

func TestStorageAmbiguousAssignmentsLeaveGroupUnchanged(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	for _, value := range []any{nil, []int{}, []int{a, a}, []int{a, 9999999}, []int{-1}, []string{"invalid"}} {
		group := f.groupDetail(t)
		group["name"] = "must not partially save"
		f.rejectGroupUpdate(t, map[string]any{"group": group, "policy_ids": value})
		f.assertGroupPolicies(t, a, b)
		require.NotEqual(t, "must not partially save", f.groupDetail(t)["name"])
	}
	group := f.groupDetail(t)
	group["edges"] = map[string]any{"storage_policies": map[string]any{"id": b}}
	f.rejectGroupUpdate(t, map[string]any{"group": group, "policy_ids": []int{a, b}})
	f.assertGroupPolicies(t, a, b)
	delete(group, "edges")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": []int{b, a}}, nil)
	f.assertGroupPolicies(t, b, a)
}

func TestStorageLegacyGroupEditsPreserveGrantsAndOrdinarySettings(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	// A legacy single-policy request still preserves the old default.
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["name"] = "legacy single-policy edit"
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.assertGroupPolicies(t, a)
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group = f.groupDetail(t)
	group["name"] = "legacy multi-policy edit"
	group["speed_limit"] = 8192
	// Omitted legacy default must preserve the actual default too.
	delete(group, "edges")
	delete(group, "storage_policy_id")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.assertGroupPolicies(t, a, b)
	reopened := f.groupDetail(t)
	require.Equal(t, "legacy multi-policy edit", reopened["name"])
	require.EqualValues(t, 8192, reopened["speed_limit"])
	f.login(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 2)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), a), policies[0].ID)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), b), policies[1].ID)
}

func TestStorageLegacyDefaultChangesRetainOtherGrants(t *testing.T) {
	f := newStorageFixture(t)
	a, b := f.policies[0].ID, f.policies[1].ID
	f.assignPolicies(t, a, b)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	group["edges"] = map[string]any{"storage_policies": map[string]any{"id": b}}
	// The obsolete scalar echo does not override the canonical legacy edge.
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.assertGroupPolicies(t, b, a)
	group = f.groupDetail(t)
	for _, clear := range []any{nil, map[string]any{"id": 0}} {
		group["edges"] = map[string]any{"storage_policies": clear}
		f.rejectGroupUpdate(t, map[string]any{"group": group})
		f.assertGroupPolicies(t, b, a)
	}
	delete(group, "edges")
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group, "policy_ids": []int{b}}, nil)
	f.assertGroupPolicies(t, b)
	f.login(t)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), b), policies[0].ID)
}

func TestStorageRetiredGroupReleasesPolicyGrants(t *testing.T) {
	f := newStorageFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	var created struct {
		ID int `json:"id"`
	}
	group := f.groupDetail(t)
	group["name"] = "Disposable unused group"
	group["id"] = 0
	f.request(t, http.MethodPut, "/api/v4/admin/group", map[string]any{"group": group, "policy_ids": []int{f.policies[0].ID, f.policies[1].ID}}, &created)
	require.Greater(t, created.ID, 3)
	policyPath := fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, policyPath, nil), "a live extra grant prevents deleting its policy")
	f.request(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/group/%d", created.ID), nil, nil)
	grants, err := f.db.GroupPolicy.Query().Where(grouppolicy.GroupID(created.ID)).Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, grants, "retired groups release formal grants")
	require.NotZero(t, f.responseCode(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/group/%d", created.ID), nil))
	f.request(t, http.MethodDelete, policyPath, nil, nil)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/group/1", nil), "system group remains protected")
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/group/2", nil), "a group with members remains protected")
	require.NotZero(t, f.responseCode(t, http.MethodDelete, "/api/v4/admin/policy/1", nil), "system/default policy remains protected")
}
