package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	entgo "entgo.io/ent"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/relocation"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	settingsvc "github.com/cloudreve/Cloudreve/v4/service/setting"
	"github.com/stretchr/testify/require"
)

func TestLoadBalanceConcurrentIndependentUpdates(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers; concurrent updates run in the database matrix")
	}
	f := newStorageFixture(t)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	policies := append([]*ent.StoragePolicy{}, f.policies...)
	for len(policies) < 6 {
		kind := types.PolicyTypeLocal
		if len(policies) == 5 {
			kind = types.PolicyTypeLoadBalance
		}
		policies = append(policies, f.db.StoragePolicy.Create().SetName(fmt.Sprint(len(policies))).SetType(kind).SaveX(ctx))
	}
	f.db.StoragePolicy.UpdateOne(policies[1]).SetType(types.PolicyTypeLoadBalance).ExecX(ctx)
	for _, pair := range [][2]int{{2, 4}, {6, 1}} {
		f.db.PolicyLoadBalance.Create().SetLoadBalanceID(policies[pair[0]-1].ID).
			SetStoragePolicyID(policies[pair[1]-1].ID).SetWeight(1).ExecX(ctx)
	}
	ready, resume := make(chan struct{}, 2), make(chan struct{})
	f.db.Setting.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if mutation.Op().Is(ent.OpCreate) {
				ready <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	done := make(chan error, 2)
	for _, pair := range [][2]int{{2, 5}, {6, 3}} {
		input := *policies[pair[0]-1]
		input.Type = types.PolicyTypeLoadBalance
		input.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: policies[pair[1]-1].ID, Weight: 1}}
		go func() {
			w := openIDRequest(t, f.router, http.MethodPut, fmt.Sprintf("/api/v4/admin/policy/%d", input.ID), map[string]any{"policy": input}, nil, f.token)
			var envelope struct{ Code int }
			err := json.Unmarshal(w.Body.Bytes(), &envelope)
			if err == nil && (w.Code != http.StatusOK || envelope.Code != 0) {
				err = fmt.Errorf("policy update failed: HTTP %d, code %d", w.Code, envelope.Code)
			}
			done <- err
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(resume)
	for range 2 {
		require.NoError(t, <-done)
	}
	for _, pair := range [][2]int{{2, 5}, {6, 3}} {
		member := policies[pair[0]-1].QueryPolicyLoadBalance().OnlyX(ctx)
		require.Equal(t, policies[pair[1]-1].ID, member.StoragePolicyID)
	}
}

func TestLoadBalancePolicyDeletionRechecksCompletedUploads(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers; concurrent deletion runs in the database matrix")
	}
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, pool.ID)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	adminToken := f.token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type deletionProbe struct{}
	ready, resume := make(chan struct{}), make(chan struct{})
	f.db.Setting.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if marked, _ := ctx.Value(deletionProbe{}).(bool); marked {
				close(ready)
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v4/admin/policy/%d", f.policies[1].ID), nil).
			WithContext(context.WithValue(ctx, deletionProbe{}, true))
		r.Header.Set("Authorization", "Bearer "+adminToken)
		f.router.ServeHTTP(w, r)
		done <- w
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f.login(t)
	uri, data := "cloudreve://my/completed-during-policy-delete.txt", []byte("completed native upload must survive policy deletion")
	session := f.upload(t, uri, data, nil)
	require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), session.StoragePolicy.ID)
	stored := f.db.Entity.Query().Where(entity.StoragePolicyEntities(f.policies[1].ID)).OnlyX(ctx)
	require.Empty(t, stored.UploadSessionID)
	input := *pool
	input.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: f.policies[0].ID, Weight: 1}}
	_, err := f.dep.StoragePolicyClient().Upsert(ctx, &input)
	require.NoError(t, err)
	close(resume)
	var w *httptest.ResponseRecorder
	select {
	case w = <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var envelope struct{ Code int }
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &envelope))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	t.Logf("Deletion returned code %d while completed entity %d still references policy %d", envelope.Code, stored.ID, f.policies[1].ID)
	require.Equal(t, data, f.readFile(t, uri))
	require.Equal(t, serializer.CodePolicyUsedByFiles, envelope.Code, w.Body.String())
}

func TestLoadBalancePolicyDeletionDoesNotInvertCopyLocks(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers")
	}
	f := newStorageFixture(t)
	pool := f.pool(t, 0, 1)
	f.assignPolicies(t, pool.ID)
	uri := "cloudreve://my/copy-source.txt"
	data := []byte("copy and policy deletion retain readable entities")
	f.upload(t, uri, data, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/copy-target", "type": "folder"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	input := *pool
	input.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: f.policies[0].ID, Weight: 1}}
	_, err := f.dep.StoragePolicyClient().Upsert(ctx, &input)
	require.NoError(t, err)
	source := f.db.File.Query().Where(entfile.Name("copy-source.txt")).WithEntities().WithMetadata().OnlyX(ctx)
	destination := f.db.File.Query().Where(entfile.Name("copy-target")).OnlyX(ctx)
	type copyProbe struct{}
	type deleteProbe struct{}
	copyReady, deleteReady, resumeCopy := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.db.File.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if marked, _ := ctx.Value(copyProbe{}).(bool); marked && mutation.Op().Is(ent.OpCreate) {
				close(copyReady)
				select {
				case <-resumeCopy:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	var atPolicy atomic.Bool
	f.db.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if marked, _ := ctx.Value(deleteProbe{}).(bool); marked && atPolicy.CompareAndSwap(false, true) {
				close(deleteReady)
			}
			return next.Mutate(ctx, mutation)
		})
	})
	copyDone, deleteDone := make(chan error, 1), make(chan error, 1)
	go func() {
		writer, tx, txCtx, err := inventory.WithTx(context.WithValue(ctx, copyProbe{}, true), f.dep.FileClient())
		if err == nil {
			defer inventory.Rollback(tx)
			err = tx.ReserveStorage(txCtx, f.dep.UserClient(), source.OwnerID, source.Size, 0)
			if err == nil {
				_, _, err = writer.Copy(txCtx, &inventory.CopyParameter{Files: []*ent.File{source}, DstMap: map[int][]*ent.File{source.FileChildren: {destination}}})
			}
			if err == nil {
				err = inventory.Commit(tx)
			}
		}
		copyDone <- err
	}()
	select {
	case <-copyReady:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		deleteDone <- f.dep.StoragePolicyClient().Delete(context.WithValue(ctx, deleteProbe{}, true), f.policies[1])
	}()
	select {
	case <-deleteReady:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	close(resumeCopy)
	copyErr, deleteErr := <-copyDone, <-deleteDone
	t.Logf("copy result: %v; policy deletion result: %v", copyErr, deleteErr)
	require.NoError(t, copyErr)
	require.ErrorIs(t, deleteErr, inventory.ErrStoragePolicyInUse)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/copy-target/copy-source.txt"))
}

func TestStorageRecursiveCopiesLockSharedEntitiesAcrossAllLayers(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers")
	}
	f := newWritableShareFixture(t)
	upper, lower := []byte("shared upper entity"), []byte("shared lower entity")
	f.upload(t, "cloudreve://my/source/upper.txt", upper, nil)
	f.upload(t, "cloudreve://my/source/nested/lower.txt", lower, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/destination", "type": "folder"}, nil)
	_, source := f.createWritableShare(t, "cloudreve://my/source", map[string]any{"everyone": "Pw=="})
	other, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, other.Email, password)
	for _, uri := range []string{"cloudreve://my/source/nested", "cloudreve://my/destination"} {
		f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
	}
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{source + "/nested/lower.txt"}, "dst": "cloudreve://my/source", "copy": true}, nil)
	f.request(t, http.MethodPost, "/api/v4/file/move", map[string]any{"uris": []string{source + "/upper.txt"}, "dst": "cloudreve://my/source/nested", "copy": true}, nil)
	require.Equal(t, 2, f.db.Entity.Query().CountX(context.Background()), "cross-owner copies share the original entities")
	ready := []chan struct{}{make(chan struct{}), make(chan struct{})}
	resume := make(chan struct{})
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(resume)
		}
	}
	t.Cleanup(release)
	var reached [2]atomic.Bool
	f.db.Entity.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			info := requestinfo.RequestInfoFromContext(ctx)
			operation := entgo.QueryFromContext(ctx)
			// Synchronize complete reference planning before either copy locks
			// entities; waiting after the first layer would block serialization.
			if info != nil && operation != nil && len(operation.Fields) == 2 && operation.Fields[1] == entity.FieldStoragePolicyEntities {
				index := -1
				if info.UserAgent == "recursive-copy-first" {
					index = 0
				} else if info.UserAgent == "recursive-copy-second" {
					index = 1
				}
				if index >= 0 && reached[index].CompareAndSwap(false, true) {
					close(ready[index])
					select {
					case <-resume:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			}
			return next.Query(ctx, query)
		})
	}))
	body := map[string]any{"uris": []string{"cloudreve://my/source"}, "dst": "cloudreve://my/destination", "copy": true}
	f.login(t)
	first := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/move", body, "recursive-copy-first")
	awaitPermissionPause(t, ready[0])
	f.loginAs(t, other.Email, password)
	second := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/move", body, "recursive-copy-second")
	select {
	case <-ready[1]:
	case result := <-second:
		t.Fatalf("second copy ended before the reference-planning barrier: %+v", result)
	case <-time.After(10 * time.Second):
		t.Fatal("second copy did not reach the reference-planning barrier")
	}
	release()
	firstResult, secondResult := awaitPermissionResult(t, first), awaitPermissionResult(t, second)
	t.Logf("concurrent recursive copy results: first=%+v second=%+v", firstResult, secondResult)
	require.Zero(t, firstResult.Code)
	require.Zero(t, secondResult.Code)
	f.login(t)
	require.Equal(t, upper, f.readFile(t, "cloudreve://my/destination/source/upper.txt"))
	require.Equal(t, lower, f.readFile(t, "cloudreve://my/destination/source/nested/lower.txt"))
	f.loginAs(t, other.Email, password)
	require.Equal(t, lower, f.readFile(t, "cloudreve://my/destination/source/lower.txt"))
	require.Equal(t, upper, f.readFile(t, "cloudreve://my/destination/source/nested/upper.txt"))
}

func TestStorageRecursiveCopyLimitRejectsBeforePartialWrites(t *testing.T) {
	f := newWritableShareFixture(t)
	data := []byte("complete bounded copy")
	f.upload(t, "cloudreve://my/source/nested/file.txt", data, nil)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/destination", "type": "folder"}, nil)
	ctx := context.Background()
	group := f.db.Group.GetX(ctx, 2)
	settings := *group.Settings
	settings.MaxWalkedFiles = 2
	f.db.Group.UpdateOne(group).SetSettings(&settings).ExecX(ctx)
	f.login(t)
	before := f.db.User.GetX(ctx, 2).Storage
	body := map[string]any{"uris": []string{"cloudreve://my/source"}, "dst": "cloudreve://my/destination", "copy": true}
	require.Equal(t, serializer.CodeFileCountLimitedReached, f.responseCode(t, http.MethodPost, "/api/v4/file/move", body))
	destination := f.db.File.Query().Where(entfile.Name("destination")).OnlyX(ctx)
	require.Zero(t, f.db.File.Query().Where(entfile.FileChildren(destination.ID)).CountX(ctx))
	require.Equal(t, before, f.db.User.GetX(ctx, 2).Storage)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/source/nested/file.txt"))
	settings.MaxWalkedFiles = 4
	f.db.Group.UpdateOne(group).SetSettings(&settings).ExecX(ctx)
	f.login(t)
	f.request(t, http.MethodPost, "/api/v4/file/move", body, nil)
	require.Equal(t, data, f.readFile(t, "cloudreve://my/destination/source/nested/file.txt"))
}

func TestStorageAdminCopyLocksOwnerGroupsBeforeReferences(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers")
	}
	f := newWritableShareFixture(t)
	data := []byte("administrator copy with concurrent group save")
	f.upload(t, "cloudreve://my/source/file.txt", data, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	settings := *f.db.Group.GetX(ctx, 1).Settings
	settings.MaxWalkedFiles = 1000
	f.db.Group.UpdateOneID(1).SetSettings(&settings).ExecX(ctx)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/destination", "type": "folder"}, nil)
	startWriter, writerReady, resumeWriter := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var started, resumed, ownerGroupRead atomic.Bool
	release := func() {
		if resumed.CompareAndSwap(false, true) {
			close(resumeWriter)
		}
	}
	t.Cleanup(release)
	f.db.Group.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			value, err := next.Query(ctx, query)
			info := requestinfo.RequestInfoFromContext(ctx)
			current, _ := ctx.Value(inventory.CurrentPermissionReadCtx{}).(bool)
			if err == nil && current && info != nil && info.UserAgent == "admin-copy-groups" {
				if groups, ok := value.([]*ent.Group); ok {
					for _, group := range groups {
						if group.ID == 2 {
							ownerGroupRead.Store(true)
						}
					}
				}
			}
			return value, err
		})
	}))
	type groupWriterKey struct{}
	var writerPaused atomic.Bool
	f.db.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			if marked, _ := ctx.Value(groupWriterKey{}).(bool); marked && writerPaused.CompareAndSwap(false, true) {
				close(writerReady)
				select {
				case <-resumeWriter:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	f.db.StoragePolicy.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			info, operation := requestinfo.RequestInfoFromContext(ctx), entgo.QueryFromContext(ctx)
			if info != nil && info.UserAgent == "admin-copy-groups" && operation != nil && len(operation.Fields) == 1 && started.CompareAndSwap(false, true) {
				close(startWriter)
				// Once the owner group is fenced first, the writer must wait
				// there instead of inside the policy/reference lock order.
				if !ownerGroupRead.Load() {
					select {
					case <-writerReady:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				value, err := next.Query(ctx, query)
				release()
				return value, err
			}
			return next.Query(ctx, query)
		})
	}))
	group := f.db.Group.GetX(ctx, 2)
	writerDone := make(chan error, 1)
	go func() {
		select {
		case <-startWriter:
		case <-ctx.Done():
			writerDone <- ctx.Err()
			return
		}
		ids := []int{f.policies[0].ID}
		_, err := f.dep.GroupClient().UpsertWithPolicies(context.WithValue(ctx, groupWriterKey{}, true), group, &ids)
		writerDone <- err
	}()
	source := "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my/source"
	result := awaitPermissionResult(t, f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/move", map[string]any{
		"uris": []string{source}, "dst": "cloudreve://my/destination", "copy": true,
	}, "admin-copy-groups"))
	writerErr := <-writerDone
	t.Logf("administrator copy: %+v; group save: %v", result, writerErr)
	require.Zero(t, result.Code)
	require.NoError(t, writerErr)
	require.True(t, started.Load(), "native copy reached the reference fence")
	require.Equal(t, data, f.readFile(t, "cloudreve://my/destination/source/file.txt"))
}

func TestStorageRecursiveCopiesOrderDistinctEntityPhysicalAliases(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers")
	}
	f := newWritableShareFixture(t)
	data := [][]byte{[]byte("first physical alias"), []byte("second physical alias")}
	for i, key := range []string{"alias-x", "alias-y"} {
		_, err := f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String(key), Body: bytes.NewReader(data[i])})
		require.NoError(t, err)
	}
	visitor, password := f.createWritableVisitor(t, 2)
	for index, id := range []int{2, visitor.ID} {
		if index == 0 {
			f.login(t)
		} else {
			f.loginAs(t, visitor.Email, password)
		}
		for _, uri := range []string{"cloudreve://my/source/nested", "cloudreve://my/destination"} {
			f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": uri, "type": "folder"}, nil)
		}
		owner, err := f.dep.UserClient().GetLoginUserByID(context.Background(), id)
		require.NoError(t, err)
		ctx := context.WithValue(context.Background(), inventory.UserCtx{}, owner)
		fm := manager.NewFileManager(f.dep, owner)
		objects, err := fm.ListPhysical(ctx, "/", f.policies[0].ID, false, func(int) {})
		require.NoError(t, err)
		require.Len(t, objects, 2)
		destination, err := fs.NewUriFromString("cloudreve://my/source")
		require.NoError(t, err)
		for _, object := range objects {
			upper := object.Source == "alias-x"
			if index == 1 {
				upper = !upper
			}
			object.RelativePath = "nested/lower.txt"
			if upper {
				object.RelativePath = "upper.txt"
			}
			require.NoError(t, fm.ImportPhysical(ctx, destination, f.policies[0].ID, object, false))
		}
		fm.Recycle()
	}
	require.Equal(t, 4, f.db.Entity.Query().CountX(context.Background()), "physical imports create distinct entity aliases")
	var written, early, paused [2]atomic.Bool
	var count atomic.Int32
	resume := make(chan struct{})
	indexFor := func(ctx context.Context) int {
		if info := requestinfo.RequestInfoFromContext(ctx); info != nil {
			if info.UserAgent == "physical-alias-copy-first" {
				return 0
			}
			if info.UserAgent == "physical-alias-copy-second" {
				return 1
			}
		}
		return -1
	}
	f.db.File.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			value, err := next.Mutate(ctx, mutation)
			if i := indexFor(ctx); i >= 0 && err == nil && mutation.Op().Is(ent.OpCreate) {
				written[i].Store(true)
			}
			return value, err
		})
	})
	f.db.StorageObject.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			value, err := next.Query(ctx, query)
			if i := indexFor(ctx); i >= 0 && err == nil {
				if !written[i].Load() {
					early[i].Store(true)
				}
				// The repaired global fence precedes writes. Only the old
				// per-layer path waits after its first, differently ordered gate.
				if !early[i].Load() && paused[i].CompareAndSwap(false, true) {
					if count.Add(1) == 2 {
						close(resume)
					}
					select {
					case <-resume:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
			}
			return value, err
		})
	}))
	body := map[string]any{"uris": []string{"cloudreve://my/source"}, "dst": "cloudreve://my/destination", "copy": true}
	f.login(t)
	first := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/move", body, "physical-alias-copy-first")
	f.loginAs(t, visitor.Email, password)
	second := f.permissionAsyncRequest(t, http.MethodPost, "/api/v4/file/move", body, "physical-alias-copy-second")
	firstResult, secondResult := awaitPermissionResult(t, first), awaitPermissionResult(t, second)
	t.Logf("physical alias copies: first=%+v second=%+v", firstResult, secondResult)
	require.Zero(t, firstResult.Code)
	require.Zero(t, secondResult.Code)
	f.login(t)
	require.Equal(t, data[0], f.readFile(t, "cloudreve://my/destination/source/upper.txt"))
	require.Equal(t, data[1], f.readFile(t, "cloudreve://my/destination/source/nested/lower.txt"))
	f.loginAs(t, visitor.Email, password)
	require.Equal(t, data[1], f.readFile(t, "cloudreve://my/destination/source/upper.txt"))
	require.Equal(t, data[0], f.readFile(t, "cloudreve://my/destination/source/nested/lower.txt"))
}

func (f *storageFixture) pool(t *testing.T, weights ...int64) *ent.StoragePolicy {
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

func (f *storageFixture) poolWeights(t *testing.T, pool *ent.StoragePolicy, weights ...int64) {
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
		"overflow":   []any{map[string]any{"storage_policy_id": f.policies[0].ID, "weight": int64(9007199254740991)}, map[string]any{"storage_policy_id": f.policies[1].ID, "weight": 1}},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, serializer.CodeParamErr, f.responseCode(t, http.MethodPut, endpoint, map[string]any{"policy": map[string]any{
				"name": "must roll back", "type": "load_balance", "edges": map[string]any{"policy_load_balance": children},
			}}))
			var saved ent.StoragePolicy
			f.request(t, http.MethodGet, endpoint, nil, &saved)
			require.Equal(t, pool.Name, saved.Name)
			require.Len(t, saved.Edges.PolicyLoadBalance, 2)
			require.Equal(t, int64(3), saved.Edges.PolicyLoadBalance[1].Weight)
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

func TestLoadBalanceLargeWeightsRetainPrecision(t *testing.T) {
	f := newStorageFixture(t)
	const weight int64 = 9007199254740991
	pool := f.pool(t, weight, 0)
	require.Equal(t, weight, pool.Edges.PolicyLoadBalance[0].Weight)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	f.request(t, http.MethodGet, fmt.Sprintf("/api/v4/admin/policy/%d", pool.ID), nil, &pool)
	require.Equal(t, weight, pool.Edges.PolicyLoadBalance[0].Weight)
	f.login(t)
	f.assignPolicies(t, pool.ID)
	var policies []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &policies)
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Children, 2)
	require.Equal(t, weight, policies[0].Children[0].Weight)
	data := []byte("large weights preserve the concrete destination")
	uri := "cloudreve://my/large-weight.txt"
	session := f.upload(t, uri, data, nil)
	require.Equal(t, policies[0].Children[0].ID, session.StoragePolicy.ID)
	require.Equal(t, data, f.readFile(t, uri))
	f.assertObjectCounts(t, 1, 0)
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
	require.Equal(t, int64(1), policies[0].Children[1].Weight)
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
