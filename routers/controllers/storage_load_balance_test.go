package controllers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	settingsvc "github.com/cloudreve/Cloudreve/v4/service/setting"
	"github.com/stretchr/testify/require"
)

func (f *storageFixture) pool(t *testing.T, weights ...int) *ent.StoragePolicy {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	children := make([]map[string]any, len(weights))
	for i, weight := range weights {
		children[i] = map[string]any{"id": 0, "load_balance_id": 0, "storage_policy_id": f.policies[i].ID, "weight": weight}
	}
	var pool ent.StoragePolicy
	f.request(t, http.MethodPut, "/api/v4/admin/policy", map[string]any{"policy": map[string]any{
		"name": "Weighted pool", "type": "load_balance", "settings": map[string]any{}, "edges": map[string]any{"policy_load_balance": children},
	}}, &pool)
	f.login(t)
	return &pool
}

func (f *storageFixture) poolWeights(t *testing.T, pool *ent.StoragePolicy, weights ...int) {
	t.Helper()
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	for i, weight := range weights {
		pool.Edges.PolicyLoadBalance[i].Weight = weight
	}
	f.request(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/policy/%d", pool.ID), map[string]any{"policy": pool}, pool)
	f.login(t)
}

func TestLoadBalanceAdministrationMatchesProRelationContract(t *testing.T) {
	f := newStorageFixture(t)
	pool := f.pool(t, 1, 3)
	require.Equal(t, "load_balance", pool.Type)
	require.Len(t, pool.Edges.PolicyLoadBalance, 2)
	for i, member := range pool.Edges.PolicyLoadBalance {
		require.Equal(t, pool.ID, member.LoadBalanceID)
		require.Equal(t, f.policies[i].ID, member.StoragePolicyID)
	}
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	endpoint := fmt.Sprintf("/api/v4/admin/policy/%d", pool.ID)
	for name, children := range map[string]any{
		"negative":   []any{map[string]any{"storage_policy_id": f.policies[0].ID, "weight": -1}},
		"fractional": []any{map[string]any{"storage_policy_id": f.policies[0].ID, "weight": 1.5}},
		"missing":    []any{map[string]any{"storage_policy_id": 999999, "weight": 1}},
		"self":       []any{map[string]any{"storage_policy_id": pool.ID, "weight": 1}},
		"null":       []any{nil},
		"duplicate":  []any{map[string]any{"storage_policy_id": f.policies[0].ID, "weight": 1}, map[string]any{"storage_policy_id": f.policies[0].ID, "weight": 2}},
		"overflow":   []any{map[string]any{"storage_policy_id": f.policies[0].ID, "weight": 9007199254740991}, map[string]any{"storage_policy_id": f.policies[1].ID, "weight": 1}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, endpoint, map[string]any{"policy": map[string]any{
				"name": "must roll back", "type": "load_balance", "edges": map[string]any{"policy_load_balance": children},
			}}))
			var saved ent.StoragePolicy
			f.request(t, http.MethodGet, endpoint, nil, &saved)
			require.Equal(t, pool.Name, saved.Name)
			require.Len(t, saved.Edges.PolicyLoadBalance, 2)
			require.Equal(t, 3, saved.Edges.PolicyLoadBalance[1].Weight)
		})
	}
	other := f.pool(t, 1)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, endpoint, map[string]any{"policy": map[string]any{
		"name": pool.Name, "type": "load_balance", "edges": map[string]any{"policy_load_balance": []any{map[string]any{"storage_policy_id": other.ID, "weight": 1}}},
	}}))
	// Older clients can edit names without submitting the relation.
	f.request(t, http.MethodPut, endpoint, map[string]any{"policy": map[string]any{"name": "Renamed pool", "type": "load_balance"}}, &pool)
	require.Len(t, pool.Edges.PolicyLoadBalance, 2)
	require.Equal(t, "Renamed pool", pool.Name)
	require.NotZero(t, f.responseCode(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID), nil))
	// Pool membership also prevents converting a child into another pool.
	require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID), map[string]any{"policy": map[string]any{"name": "Nested", "type": "load_balance"}}))
	f.request(t, http.MethodDelete, endpoint, nil, nil)
	f.request(t, http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID), nil, nil)
}

func TestLoadBalanceDescriptorsAndExplicitChildAuthorization(t *testing.T) {
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, pool.ID)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), pool.ID), policies[0].ID)
	require.EqualValues(t, types.PolicyTypeLoadBalance, policies[0].Type)
	require.Len(t, policies[0].Children, 2)
	require.Zero(t, policies[0].Children[0].Weight)
	require.Equal(t, 1, policies[0].Children[1].Weight)
	raw, err := json.Marshal(policies)
	require.NoError(t, err)
	for _, forbidden := range []string{"secret_key", "access_key", "settings", "bucket_name", "server", f.policies[0].SecretKey} {
		require.NotContains(t, string(raw), forbidden)
	}
	session := f.upload(t, "cloudreve://my/explicit-child.txt", []byte("API may explicitly use zero-weight A"), policies[0].Children[0].ID)
	require.Equal(t, policies[0].Children[0].ID, session.StoragePolicy.ID)
	f.upload(t, "cloudreve://my/automatic.txt", []byte("automatic writes use B"), nil)
	f.upload(t, "cloudreve://my/explicit-pool.txt", []byte("explicit pool writes use B"), policies[0].ID)
	f.assertObjectCounts(t, 1, 2)
	f.assignPolicies(t, f.policies[0].ID)
	require.Equal(t, serializer.CodeGroupNotAllowed, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/revoked.txt", "size": 1, "policy_id": policies[0].Children[1].ID}))
	require.Equal(t, []byte("automatic writes use B"), f.readFile(t, "cloudreve://my/automatic.txt"))
}

func TestLoadBalanceRejectsConvertingPopulatedPhysicalPolicy(t *testing.T) {
	f := newStorageFixture(t)
	f.login(t)
	uri := "cloudreve://my/existing-physical.txt"
	data := []byte("existing physical data must retain a working driver")
	f.upload(t, uri, data, nil)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[0].ID), map[string]any{"policy": map[string]any{
		"name": "Unsafe conversion", "type": types.PolicyTypeLoadBalance,
		"edges": map[string]any{"policy_load_balance": []any{map[string]any{"storage_policy_id": f.policies[1].ID, "weight": 1}}},
	}}))
	f.login(t)
	require.Equal(t, data, f.readFile(t, uri))
}

func TestLoadBalanceUploadSessionAndFilePreferenceRemainStable(t *testing.T) {
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, f.policies[0].ID, pool.ID)
	poolID := hashid.EncodePolicyID(f.dep.HashIDEncoder(), pool.ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/pooled", "type": "folder"}, nil)
	f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": "cloudreve://my/pooled", "policy_id": poolID}, nil)
	uri := "cloudreve://my/pooled/retained.txt"
	data := []byte("session stays on B after weights change")
	var session explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data)}, &session)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	require.Equal(t, b, session.StoragePolicy.ID)
	f.poolWeights(t, pool, 1, 0)
	f.finishUpload(t, session, data)
	require.Equal(t, data, f.readFile(t, uri))
	info := f.fileInfo(t, uri)
	require.Equal(t, b, info.ExtendedInfo.StoragePolicy.ID, "existing files retain the actual child selected on creation")
	version := []byte("next version remains on B despite its zero weight")
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(version), "entity_type": "version"}, &session)
	require.Equal(t, b, session.StoragePolicy.ID)
	f.finishUpload(t, session, version)
	fresh := f.upload(t, "cloudreve://my/pooled/new-after-weight-change.txt", []byte("new files select A"), nil)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID), fresh.StoragePolicy.ID)
	f.poolWeights(t, pool, 0, 1)
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data), "entity_type": "version"}, &session)
	require.Equal(t, b, session.StoragePolicy.ID, "new versions keep the original concrete policy")
	f.finishUpload(t, session, data)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/pooled"), nil, &listing)
	require.Equal(t, poolID, listing.StoragePolicy.ID)
	bad, err := f.db.Entity.Query().Where(entity.StoragePolicyEntities(pool.ID)).Count(context.Background())
	require.NoError(t, err)
	require.Zero(t, bad, "a logical pool must never be an entity's physical location")
}

func TestLoadBalanceDisabledAndEmptyPoolsHaveNoUploadSideEffects(t *testing.T) {
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 0)
	f.assignPolicies(t, pool.ID)
	before, err := f.db.Entity.Query().Count(context.Background())
	require.NoError(t, err)
	for _, uri := range []string{"cloudreve://my/disabled.txt", "cloudreve://my/not-created/deep/file.txt"} {
		require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": 1}))
	}
	after, err := f.db.Entity.Query().Count(context.Background())
	require.NoError(t, err)
	require.Equal(t, before, after)
	exists, err := f.db.File.Query().Where(entfile.Name("not-created")).Exist(context.Background())
	require.NoError(t, err)
	require.False(t, exists)
	f.assertObjectCounts(t, 0, 0)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	pool.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{}
	f.request(t, http.MethodPut, fmt.Sprintf("/api/v4/admin/policy/%d", pool.ID), map[string]any{"policy": map[string]any{"name": pool.Name, "type": pool.Type, "edges": map[string]any{"policy_load_balance": []any{}}}}, nil)
	var empty ent.StoragePolicy
	f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/policy/%d", pool.ID), nil, &empty)
	require.Empty(t, empty.Edges.PolicyLoadBalance)
	f.login(t)
	require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/empty-pool.txt", "size": 0}))
}

func TestLoadBalanceEmptyFileFixesItsPolicyOnFirstContentUpload(t *testing.T) {
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, pool.ID)
	uri := "cloudreve://my/initially-empty.txt"
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "file"}, nil)
	var session explorer.UploadSessionResponse
	data := []byte("first actual content fixes child B")
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data), "entity_type": "version"}, &session)
	f.finishUpload(t, session, data)
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	require.Equal(t, b, f.fileInfo(t, uri).ExtendedInfo.StoragePolicy.ID)
	f.poolWeights(t, pool, 1, 0)
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data), "entity_type": "version"}, &session)
	require.Equal(t, b, session.StoragePolicy.ID)
	f.finishUpload(t, session, data)
}

func TestLoadBalanceWebDAVUsesConcreteDestination(t *testing.T) {
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, pool.ID)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	group := f.groupDetail(t)
	permissions := &boolset.BooleanSet{}
	boolset.Set(types.GroupPermissionWebDAV, true, permissions)
	boolset.Set(types.GroupPermissionWebDAVProxy, true, permissions)
	group["permissions"] = permissions
	f.request(t, http.MethodPut, "/api/v4/admin/group/2", map[string]any{"group": group}, nil)
	f.login(t)
	var account settingsvc.DavAccount
	f.request(t, http.MethodPut, "/api/v4/devices/dav", map[string]any{"name": "Pool DAV", "uri": "cloudreve://my", "proxy": true}, &account)
	for i, data := range []string{"WebDAV on B", "WebDAV on A"} {
		if i == 1 {
			f.poolWeights(t, pool, 1, 0)
		}
		w := f.binaryRequest(t, http.MethodPut, fmt.Sprintf("/dav/pool-%d.txt", i), []byte(data), "storage@example.com", account.Password)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		require.Equal(t, data, string(f.readFile(t, fmt.Sprintf("cloudreve://my/pool-%d.txt", i))))
	}
	f.assertObjectCounts(t, 1, 1)
}

func TestLoadBalanceMixedLocalAndS3Uploads(t *testing.T) {
	f := newStorageFixture(t)
	local, err := f.db.StoragePolicy.Create().SetName("Local pool member").SetType("local").
		SetDirNameRule(filepath.Join(t.TempDir(), "objects")).SetFileNameRule("{uuid}_{originname}").
		SetSettings(&types.PolicySetting{ChunkSize: 5 << 20}).Save(context.Background())
	require.NoError(t, err)
	f.policies = append(f.policies, local)
	pool := f.pool(t, 0, 0, 1)
	f.assignPolicies(t, pool.ID)
	data := []byte("a mixed pool writes through the ordinary local driver")
	uri := "cloudreve://my/mixed-local.txt"
	var session explorer.UploadSessionResponse
	f.request(t, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": uri, "size": len(data)}, &session)
	require.EqualValues(t, types.PolicyTypeLocal, session.StoragePolicy.Type)
	w := f.binaryRequest(t, http.MethodPost, "/api/v4/file/upload/"+session.SessionID+"/0", data, "", "")
	var receipt struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &receipt), w.Body.String())
	require.Zero(t, receipt.Code, w.Body.String())
	info := f.fileInfo(t, uri)
	id, err := f.dep.HashIDEncoder().Decode(info.PrimaryEntity, hashid.EntityID)
	require.NoError(t, err)
	model, err := f.db.Entity.Get(context.Background(), id)
	require.NoError(t, err)
	actual, err := os.ReadFile(model.Source)
	require.NoError(t, err)
	require.Equal(t, data, actual)
	f.poolWeights(t, pool, 0, 1, 0)
	f.upload(t, "cloudreve://my/mixed-s3.txt", []byte("the same logical pool now writes to S3"), nil)
	var links explorer.FileURLResponse
	f.request(t, http.MethodPost, "/api/v4/file/url", map[string]any{"uris": []string{uri}}, &links)
	target, err := url.Parse(links.Urls[0].Url)
	require.NoError(t, err)
	w = f.binaryRequest(t, http.MethodGet, target.RequestURI(), nil, "", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, data, w.Body.Bytes(), "changing pool weights leaves the existing local file readable")
}

func TestLoadBalanceRelocationPersistsConcreteTargetsAcrossWorkerRestart(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, f.policies[0].ID, pool.ID)
	f.enableMigration(t, true)
	for _, name := range []string{"first", "second"} {
		f.upload(t, "cloudreve://my/relocate-pool/"+name+".txt", []byte("durable pool relocation "+name), hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID))
	}
	poolID := hashid.EncodePolicyID(f.dep.HashIDEncoder(), pool.ID)
	sources := []string{"cloudreve://my/relocate-pool"}
	var task explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/reloacte", map[string]any{"src": sources, "dst_policy_id": poolID}, &task)
	jobID, err := f.dep.HashIDEncoder().Decode(task.ID, hashid.TaskID)
	require.NoError(t, err)
	_, err = relocation.AdvanceSingle(context.Background(), f.dep, jobID, 2, sources, pool.ID)
	require.NoError(t, err)
	items, err := f.db.RelocationItem.Query().Where(relocationitem.TaskID(jobID)).All(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2)
	for _, item := range items {
		require.Equal(t, f.policies[1].ID, item.DestinationPolicyID)
	}
	f.poolWeights(t, pool, 1, 0)
	f.recycling = true
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	completed := f.waitForStorageTask(t, task.ID, "completed")
	require.Equal(t, poolID, completed.Summary.Props["dst_policy_id"])
	for _, name := range []string{"first", "second"} {
		uri := "cloudreve://my/relocate-pool/" + name + ".txt"
		info := f.fileInfo(t, uri)
		require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), info.ExtendedInfo.Entities[0].StoragePolicy.ID)
		require.Equal(t, []byte("durable pool relocation "+name), f.readFile(t, uri))
	}
}

func TestLoadBalanceArchiveAndExtractUseConcretePolicies(t *testing.T) {
	f := newStorageFixtureWithLegacy(t, true)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, f.policies[0].ID, pool.ID)
	f.enableArchive(t)
	data := []byte("background writers resolve the virtual pool before provider I/O")
	f.upload(t, "cloudreve://my/pool-input.txt", data, nil)
	folder := "cloudreve://my/pool-output"
	poolID := hashid.EncodePolicyID(f.dep.HashIDEncoder(), pool.ID)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": folder, "type": "folder"}, nil)
	f.request(t, http.MethodPatch, "/api/v4/file/policy", map[string]any{"uri": folder, "policy_id": poolID}, nil)
	archive := folder + "/archive.zip"
	var accepted explorer.TaskResponse
	f.request(t, http.MethodPost, "/api/v4/workflow/archive", map[string]any{"src": []string{"cloudreve://my/pool-input.txt"}, "dst": archive}, &accepted)
	f.poolWeights(t, pool, 1, 0)
	worker := launchStorageWorkerWithWorkflows(t, f)
	f.remote = worker.ready(t)
	f.login(t)
	f.waitForStorageTask(t, accepted.ID, "completed")
	b := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	require.Equal(t, b, f.fileInfo(t, archive).ExtendedInfo.Entities[0].StoragePolicy.ID, "queued archive retains its chosen child after weights change")
	f.poolWeights(t, pool, 0, 1)
	unpacked := folder + "/unpacked"
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": unpacked, "type": "folder"}, nil)
	f.request(t, http.MethodPost, "/api/v4/workflow/extract", map[string]any{"src": []string{archive}, "dst": unpacked}, &accepted)
	f.waitForStorageTask(t, accepted.ID, "completed")
	result := unpacked + "/pool-input.txt"
	require.Equal(t, b, f.fileInfo(t, result).ExtendedInfo.Entities[0].StoragePolicy.ID)
	require.Equal(t, data, f.readFile(t, result))
}
