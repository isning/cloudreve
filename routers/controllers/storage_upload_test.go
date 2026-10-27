package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/node"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	policyresolver "github.com/cloudreve/Cloudreve/v4/pkg/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

func TestStorageWritesRevalidateReceivingQuotaAfterCachedNavigation(t *testing.T) {
	for _, operation := range []string{"upload", "copy"} {
		for _, scope := range []string{"personal", "share", "inherited-share"} {
			for _, change := range []string{"reduced", "increased"} {
				t.Run(fmt.Sprintf("%s/%s/%s", operation, scope, change), func(t *testing.T) {
					if scope == "inherited-share" && os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
						t.Skip("MySQL repeatable-read accepting transaction")
					}
					f := newWritableShareFixture(t)
					data := bytes.Repeat([]byte("q"), 20)
					f.upload(t, "cloudreve://my/work/source.txt", data, nil)
					f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/work/destination", "type": "folder"}, nil)
					ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					defer cancel()
					actorID, root := 2, "cloudreve://my/work"
					if scope != "personal" {
						_, root = f.createWritableShare(t, root, map[string]any{"everyone": "Pw=="})
						visitor, _ := f.createWritableVisitor(t, 2)
						actorID = visitor.ID
					}
					oldLimit, newLimit := int64(100), int64(30)
					if change == "increased" {
						oldLimit, newLimit = newLimit, oldLimit
					}
					setQuota := func(limit int64) {
						group := f.db.Group.GetX(ctx, 2)
						group.MaxStorage = limit
						_, err := f.dep.GroupClient().UpsertWithPolicies(ctx, group, nil)
						require.NoError(t, err)
					}
					setQuota(oldLimit)
					actor, err := f.dep.UserClient().GetLoginUserByID(ctx, actorID)
					require.NoError(t, err)
					ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
					fm := manager.NewFileManager(f.dep, actor)
					defer fm.Recycle()
					rootURI, err := fs.NewUriFromString(root)
					require.NoError(t, err)
					destination := rootURI.Join("destination")
					cached, err := fm.Get(ctx, destination)
					require.NoError(t, err)
					require.Equal(t, oldLimit, cached.Owner().Edges.Group.MaxStorage)
					require.Equal(t, int64(len(data)), cached.Owner().Storage)
					var tx *inventory.Tx
					acceptCtx := ctx
					if scope == "inherited-share" {
						writer, outer, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
						require.NoError(t, err)
						tx, acceptCtx = outer, txCtx
						defer inventory.Rollback(tx)
						writer.GetClient().Group.Query().CountX(acceptCtx)
					}
					setQuota(newLimit)
					beforeFiles := f.db.File.Query().CountX(ctx)
					beforeEntities := f.db.Entity.Query().CountX(ctx)
					beforeObjects := f.db.StorageObject.Query().CountX(ctx)
					beforeStorage := f.db.User.GetX(ctx, 2).Storage
					require.Equal(t, int64(len(data)), beforeStorage)
					var session *fs.UploadSession
					var req *fs.UploadRequest
					if operation == "upload" {
						req = &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(data)), Props: &fs.UploadProps{
							Uri: destination.Join("current.txt"), Size: int64(len(data)), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
						}}
						session, err = fm.PrepareUpload(acceptCtx, req)
					} else {
						err = fm.MoveOrCopy(acceptCtx, []*fs.URI{rootURI.Join("source.txt")}, destination, true)
					}
					if change == "reduced" {
						require.ErrorIs(t, err, fs.ErrInsufficientCapacity)
						if tx != nil {
							require.NoError(t, inventory.CommitWithStorageDiff(acceptCtx, tx, f.dep.Logger(), f.dep.UserClient()))
						}
						require.Equal(t, beforeFiles, f.db.File.Query().CountX(ctx))
						require.Equal(t, beforeEntities, f.db.Entity.Query().CountX(ctx))
						require.Equal(t, beforeObjects, f.db.StorageObject.Query().CountX(ctx))
						require.Equal(t, beforeStorage, f.db.User.GetX(ctx, 2).Storage)
						f.assertObjectCounts(t, 1, 0)
						return
					}
					require.NoError(t, err)
					if tx != nil {
						require.NoError(t, inventory.CommitWithStorageDiff(acceptCtx, tx, f.dep.Logger(), f.dep.UserClient()))
					}
					name := "source.txt"
					if operation == "upload" {
						require.NoError(t, fm.Upload(ctx, req, session.Policy, session))
						_, err = fm.CompleteUpload(ctx, session)
						require.NoError(t, err)
						name = "current.txt"
					}
					require.Equal(t, beforeStorage+int64(len(data)), f.db.User.GetX(ctx, 2).Storage)
					require.Equal(t, data, f.readFile(t, "cloudreve://my/work/destination/"+name))
					if actorID != 2 {
						require.Zero(t, f.db.User.GetX(ctx, actorID).Storage)
					}
				})
			}
		}
	}
}

func TestStoragePolicySelectionUsesInheritedTransaction(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	original := f.db.Group.GetX(ctx, 2).Name
	writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.StoragePolicyClient())
	require.NoError(t, err)
	defer inventory.Rollback(tx)
	writer.GetClient().Group.UpdateOneID(2).SetName("Pending group name").ExecX(txCtx)
	chosen, err := policyresolver.New(f.dep.UserClient(), f.dep.StoragePolicyClient()).Select(txCtx, 2, f.policies[0].ID, 0)
	require.NoError(t, err)
	require.Equal(t, f.policies[0].ID, chosen.ID)
	require.Equal(t, "Pending group name", writer.GetClient().Group.GetX(txCtx, 2).Name)
	require.NoError(t, inventory.Rollback(tx))
	require.Equal(t, original, f.db.Group.GetX(ctx, 2).Name)
}

func TestStorageAutomaticUploadUsesCurrentAndPendingFolderPreferences(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("MySQL repeatable-read placement ancestry")
	}
	for _, mode := range []string{"rebound", "new-folder", "pending-binding"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t)
			f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			if mode != "new-folder" {
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/bound", "type": "folder"}, nil)
				f.bindFolder(t, "cloudreve://my/bound", 0)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			writer.GetClient().File.Query().CountX(txCtx)
			if mode == "new-folder" {
				f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/bound", "type": "folder"}, nil)
			}
			if mode == "pending-binding" {
				bound := writer.GetClient().File.Query().Where(file.Name("bound")).OnlyX(txCtx)
				writer.GetClient().File.UpdateOne(bound).SetStoragePolicyFiles(f.policies[1].ID).ExecX(txCtx)
			} else {
				f.bindFolder(t, "cloudreve://my/bound", 1)
			}
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			uri, err := fs.NewUriFromString("cloudreve://my/bound/current.txt")
			require.NoError(t, err)
			data := []byte("automatic upload follows the accepting ancestry")
			req := &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(data)), Props: &fs.UploadProps{
				Uri: uri, Size: int64(len(data)), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
			}}
			session, err := fm.PrepareUpload(txCtx, req)
			require.NoError(t, err)
			require.Equal(t, f.policies[1].ID, session.Policy.ID)
			require.NoError(t, inventory.Commit(tx))
			require.Equal(t, 1, f.db.File.Query().Where(file.OwnerID(2), file.Name(inventory.RootFolderName)).CountX(ctx))
			require.NoError(t, fm.Upload(ctx, req, session.Policy, session))
			_, err = fm.CompleteUpload(ctx, session)
			require.NoError(t, err)
			require.Equal(t, data, f.readFile(t, uri.String()))
		})
	}
}

func TestStoragePhysicalImportSurvivesPolicyCacheEviction(t *testing.T) {
	f := newStorageFixture(t)
	f.request(t, http.MethodPost, "/api/v4/file/create", map[string]any{"uri": "cloudreve://my/imported", "type": "folder"}, nil)
	data := []byte("physical import after native policy cache eviction")
	_, err := f.s3.PutObject(&s3.PutObjectInput{Bucket: aws.String(f.policies[0].BucketName), Key: aws.String("import-cache-source"), Body: bytes.NewReader(data)})
	require.NoError(t, err)
	ctx := context.Background()
	owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
	require.NoError(t, err)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(f.dep, owner)
	defer fm.Recycle()
	objects, err := fm.ListPhysical(ctx, "/", f.policies[0].ID, false, func(int) {})
	require.NoError(t, err)
	require.Len(t, objects, 1)
	input := *f.policies[0]
	input.Name += " refreshed"
	_, err = f.dep.StoragePolicyClient().Upsert(ctx, &input)
	require.NoError(t, err)
	destination, err := fs.NewUriFromString("cloudreve://my/imported")
	require.NoError(t, err)
	importCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, fm.ImportPhysical(importCtx, destination, input.ID, objects[0], false))
	require.Equal(t, data, f.readFile(t, "cloudreve://my/imported/import-cache-source"))
}

func TestStorageUploadPlanningDoesNotWaitForTheFullTransactionPool(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") != "mysql" {
		t.Skip("native MySQL/MariaDB upload committed-metadata path")
	}
	f := newStorageFixture(t)
	f.upload(t, "cloudreve://my/target/seed.txt", []byte("existing upload directory"), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
	require.NoError(t, err)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(f.dep, owner)
	defer fm.Recycle()
	type firstUpload struct{}
	locked, resume := make(chan struct{}), make(chan struct{})
	var paused, released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(resume)
		}
	}
	defer release()
	f.db.User.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			value, err := next.Mutate(ctx, mutation)
			marked, _ := ctx.Value(firstUpload{}).(bool)
			if marked && err == nil && paused.CompareAndSwap(false, true) {
				close(locked)
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return value, err
		})
	})
	uri, err := fs.NewUriFromString("cloudreve://my/target/accepted.txt")
	require.NoError(t, err)
	prepareCtx, stop := context.WithTimeout(context.WithValue(ctx, firstUpload{}, true), 15*time.Second)
	defer stop()
	prepared := make(chan error, 1)
	go func() {
		_, err := fm.PrepareUpload(prepareCtx, &fs.UploadRequest{Props: &fs.UploadProps{Uri: uri, UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute)}})
		prepared <- err
	}()
	awaitPermissionPause(t, locked)
	var fillers []*ent.Tx
	var cancels []context.CancelFunc
	defer func() {
		for i, tx := range fillers {
			_ = tx.Rollback()
			cancels[i]()
		}
	}()
	full := false
	for range 100 {
		openCtx, stopOpen := context.WithCancel(ctx)
		type opened struct {
			tx  *ent.Tx
			err error
		}
		result := make(chan opened, 1)
		go func() { tx, err := f.db.Tx(openCtx); result <- opened{tx, err} }()
		select {
		case opened := <-result:
			if opened.err != nil {
				stopOpen()
				t.Fatal(opened.err)
			}
			fillers, cancels = append(fillers, opened.tx), append(cancels, stopOpen)
		case <-time.After(500 * time.Millisecond):
			stopOpen()
			opened := <-result
			if opened.tx != nil {
				_ = opened.tx.Rollback()
			}
			full = true
		}
		if full {
			break
		}
	}
	require.True(t, full, "native transaction pool must be full before resuming upload planning")
	require.GreaterOrEqual(t, len(fillers), 95)
	t.Logf("held %d native transactions in addition to the upload", len(fillers))
	release()
	require.NoError(t, <-prepared)
	require.True(t, f.db.File.Query().Where(file.OwnerID(2), file.Name("accepted.txt")).ExistX(ctx))
}

func TestStorageThumbnailBypassLocksOwnersBeforeCurrentAncestry(t *testing.T) {
	if os.Getenv("OIDC_TEST_DRIVER") == "" {
		t.Skip("SQLite serializes writers")
	}
	f := newWritableShareFixture(t)
	f.upload(t, "cloudreve://my/team/source.txt", []byte("thumbnail source"), nil)
	_, share := f.createWritableShare(t, "cloudreve://my/team", map[string]any{"everyone": "IQ=="})
	visitor, password := f.createWritableVisitor(t, 2)
	f.loginAs(t, visitor.Email, password)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	actor, err := f.dep.UserClient().GetLoginUserByID(ctx, visitor.ID)
	require.NoError(t, err)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
	fm := manager.NewFileManager(f.dep, actor)
	defer fm.Recycle()
	uri, err := fs.NewUriFromString(share + "/source.txt")
	require.NoError(t, err)
	request := func() *fs.UploadRequest {
		kind := types.EntityTypeThumbnail
		return &fs.UploadRequest{Props: &fs.UploadProps{Uri: uri, EntityType: &kind, UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute)}}
	}
	_, err = fm.PrepareUpload(ctx, request())
	require.Error(t, err, "read-only visitors cannot update without the native thumbnail bypass")
	type thumbnailKey struct{}
	var ownerLocked, paused atomic.Bool
	fileReady, resume, deleteReady := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(resume)
		}
	}
	t.Cleanup(release)
	f.db.User.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			value, err := next.Mutate(ctx, mutation)
			if marked, _ := ctx.Value(thumbnailKey{}).(bool); marked && err == nil {
				if added, ok := mutation.(*ent.UserMutation).AddedStorage(); ok && added == 0 {
					ownerLocked.Store(true)
				}
			}
			return value, err
		})
	})
	f.db.File.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			value, err := next.Query(ctx, query)
			marked, _ := ctx.Value(thumbnailKey{}).(bool)
			current, _ := ctx.Value(inventory.CurrentPermissionReadCtx{}).(bool)
			if marked && current && err == nil && paused.CompareAndSwap(false, true) {
				close(fileReady)
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return value, err
		})
	}))
	prepared := make(chan error, 1)
	go func() {
		_, err := fm.PrepareUpload(dbfs.WithBypassOwnerCheck(context.WithValue(ctx, thumbnailKey{}, true)), request())
		prepared <- err
	}()
	awaitPermissionPause(t, fileReady)
	deleted := make(chan error, 1)
	go func() {
		fc, tx, deleteCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
		if err == nil {
			defer inventory.Rollback(tx)
			err = inventory.LockPermissionOwners(deleteCtx, fc.GetClient(), 2)
			if err == nil {
				close(deleteReady)
				err = fc.DeleteByUser(deleteCtx, 2)
			}
			if err == nil {
				err = inventory.Commit(tx)
			}
		}
		deleted <- err
	}()
	// A repaired thumbnail already holds the owner; deletion must then wait
	// outside the file lock. The old path can acquire that owner first.
	if !ownerLocked.Load() {
		awaitPermissionPause(t, deleteReady)
	}
	release()
	prepareErr, deleteErr := <-prepared, <-deleted
	t.Logf("thumbnail preparation=%v; native owner file deletion=%v", prepareErr, deleteErr)
	require.NoError(t, prepareErr)
	require.NoError(t, deleteErr)
}

func TestStorageConcurrentPoolUploadsRejectChangedMemberships(t *testing.T) {
	f := newStorageFixture(t)
	if f.database.Type != "mysql" && f.database.Type != "postgres" {
		t.Skip("SQLite serializes writers; row-lock ordering runs in the database matrix")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, q := f.pool(t, 1, 0), f.pool(t, 0, 1)
	p.Edges.PolicyLoadBalance = p.Edges.PolicyLoadBalance[:1]
	q.Edges.PolicyLoadBalance = q.Edges.PolicyLoadBalance[1:]
	for _, pool := range []*ent.StoragePolicy{p, q} {
		_, err := f.dep.StoragePolicyClient().Upsert(ctx, pool)
		require.NoError(t, err)
	}
	f.assignPolicies(t, p.ID, q.ID)
	// Different owners in the same group must not rely on a shared owner lock.
	f.db.User.UpdateOneID(1).SetGroupUsers(2).ExecX(ctx)
	f.loginAs(t, "storage-admin@example.com", f.adminPassword)
	tokens := []string{f.token}
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
	f.login(t)
	tokens = append(tokens, f.token)
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
	type probeKey struct{}
	type uploadProbe struct{ atPolicy, atGrant atomic.Bool }
	selected, resume := make(chan struct{}, 2), make(chan struct{})
	logicalReadsDone := make(chan struct{})
	var logicalReads, grantQueryErrors atomic.Int32
	f.db.StoragePolicy.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			probe, _ := ctx.Value(probeKey{}).(*uploadProbe)
			m := mutation.(*ent.StoragePolicyMutation)
			if _, ok := m.AddedMaxSize(); ok && probe != nil && probe.atPolicy.CompareAndSwap(false, true) {
				selected <- struct{}{}
				select {
				case <-resume:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return next.Mutate(ctx, mutation)
		})
	})
	f.db.GroupPolicy.Intercept(ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			value, err := next.Query(ctx, query)
			if err != nil {
				grantQueryErrors.Add(1)
			}
			probe, _ := ctx.Value(probeKey{}).(*uploadProbe)
			ids, _ := value.([]int)
			// Synchronize successful grant reads to exercise the old separate
			// logical/concrete checks. The combined membership check rejects
			// both stale selections without acquiring opposite grant rows.
			if err == nil && len(ids) > 0 && probe != nil && probe.atGrant.CompareAndSwap(false, true) {
				if logicalReads.Add(1) == 2 {
					close(logicalReadsDone)
				}
				select {
				case <-logicalReadsDone:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return value, err
		})
	}))
	done := make(chan storageResponse, 2)
	for i, pool := range []*ent.StoragePolicy{p, q} {
		raw, err := json.Marshal(map[string]any{
			"uri": "cloudreve://my/concurrent.txt", "size": 0,
			"policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), pool.ID),
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPut, "/api/v4/file/upload", bytes.NewReader(raw)).WithContext(context.WithValue(ctx, probeKey{}, &uploadProbe{}))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tokens[i])
		go func() {
			response := httptest.NewRecorder()
			f.router.ServeHTTP(response, req)
			var envelope storageResponse
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || response.Code != http.StatusOK {
				envelope.Code = serializer.CodeDBError
			}
			done <- envelope
		}()
	}
	for range 2 {
		select {
		case <-selected:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	p.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: f.policies[1].ID, Weight: 1}}
	q.Edges.PolicyLoadBalance = []*ent.PolicyLoadBalance{{StoragePolicyID: f.policies[0].ID, Weight: 1}}
	for _, pool := range []*ent.StoragePolicy{p, q} {
		_, err := f.dep.StoragePolicyClient().Upsert(ctx, pool)
		require.NoError(t, err)
	}
	close(resume)
	for range 2 {
		select {
		case result := <-done:
			require.Equal(t, serializer.CodeGroupNotAllowed, result.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	require.Zero(t, grantQueryErrors.Load(), "grant rejection must not conceal a database deadlock")
	require.Zero(t, f.db.File.Query().Where(file.Name("concurrent.txt")).CountX(ctx))
	require.Zero(t, f.db.Entity.Query().CountX(ctx))
}

func TestStorageUploadRejectsRevokedGrantInInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"direct", "pool-child"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f.assignPolicies(t, f.policies[0].ID)
			var poolID int
			if mode == "pool-child" {
				pool := f.pool(t, 1, 0)
				pool.Edges.PolicyLoadBalance = pool.Edges.PolicyLoadBalance[:1]
				pool, err := f.dep.StoragePolicyClient().Upsert(ctx, pool)
				require.NoError(t, err)
				poolID = pool.ID
				f.assignPolicies(t, poolID)
			}
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			before := f.db.User.GetX(ctx, 2).Storage
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, 1, writer.GetClient().GroupPolicy.Query().Where(grouppolicy.GroupID(2)).CountX(txCtx))
			if poolID > 0 {
				pool := f.db.StoragePolicy.Query().Where(storagepolicy.ID(poolID)).WithPolicyLoadBalance().OnlyX(ctx)
				pool.Edges.PolicyLoadBalance = pool.Edges.PolicyLoadBalance[1:]
				_, err = f.dep.StoragePolicyClient().Upsert(ctx, pool)
				require.NoError(t, err)
			} else {
				f.assignPolicies(t, f.policies[1].ID)
			}
			raw, err := json.Marshal(map[string]any{
				"uri": "cloudreve://my/revoked.txt", "size": 0,
				"policy_id": hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID),
			})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPut, "/api/v4/file/upload", bytes.NewReader(raw)).WithContext(txCtx)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+f.token)
			response := httptest.NewRecorder()
			f.router.ServeHTTP(response, req)
			require.Equal(t, http.StatusOK, response.Code)
			var envelope storageResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
			require.Equal(t, serializer.CodeGroupNotAllowed, envelope.Code)
			require.NoError(t, inventory.Commit(tx))
			require.Equal(t, before, f.db.User.GetX(ctx, 2).Storage)
			require.Zero(t, f.db.File.Query().Where(file.Name("revoked.txt")).CountX(ctx))
			require.Zero(t, f.db.Entity.Query().CountX(ctx))
			for _, policy := range f.policies {
				objects, err := f.s3.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
				require.NoError(t, err)
				require.Empty(t, objects.Contents)
			}
		})
	}
}

func TestStorageUploadUsesCurrentGrantsInInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"explicit", "automatic", "new-policy"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f.assignPolicies(t, f.policies[0].ID)
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			owner := f.db.User.Query().Where(user.ID(2)).WithGroup().OnlyX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, 1, writer.GetClient().GroupPolicy.Query().Where(grouppolicy.GroupID(2)).CountX(txCtx))
			destination := f.policies[1]
			if mode == "new-policy" {
				input := *destination
				input.ID, input.Name = 0, "Newly committed upload destination"
				destination, err = f.dep.StoragePolicyClient().Upsert(ctx, &input)
				require.NoError(t, err)
			}
			f.assignPolicies(t, destination.ID)
			uri := "cloudreve://my/current.txt"
			payload := []byte("accepted using the current grant")
			path, err := fs.NewUriFromString(uri)
			require.NoError(t, err)
			req := &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(payload)), Props: &fs.UploadProps{
				Uri: path, Size: int64(len(payload)), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
			}}
			if mode != "automatic" {
				req.Props.PreferredStoragePolicy = destination.ID
			}
			ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			session, err := fm.PrepareUpload(txCtx, req)
			require.NoError(t, err)
			require.Equal(t, destination.ID, session.Policy.ID)
			require.NoError(t, inventory.Commit(tx))
			require.NoError(t, fm.Upload(ctx, req, session.Policy, session))
			_, err = fm.CompleteUpload(ctx, session)
			require.NoError(t, err)
			require.Equal(t, payload, f.readFile(t, uri))
			require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), destination.ID), f.fileInfo(t, uri).ExtendedInfo.StoragePolicy.ID)
		})
	}
}

func TestStorageUploadUsesCurrentRemoteNodeInInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"new-node", "updated-node"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t)
			if f.database.Type == "sqlite" {
				t.Skip("SQLite serializes the independent node writer")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f.assignPolicies(t, f.policies[0].ID)
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			var destination *ent.StoragePolicy
			createDestination := func() {
				n := f.db.Node.Create().SetName("Current remote node").SetType(node.TypeSlave).
					SetStatus(node.StatusActive).SetServer("https://initial-node.example.com").
					SetCapabilities(&boolset.BooleanSet{}).SaveX(ctx)
				input := *f.policies[1]
				input.ID, input.Name, input.Type = 0, "Current remote destination", types.PolicyTypeRemote
				input.NodeID = n.ID
				var err error
				destination, err = f.dep.StoragePolicyClient().Upsert(ctx, &input)
				require.NoError(t, err)
				f.assignPolicies(t, destination.ID)
			}
			if mode == "updated-node" {
				createDestination()
			}
			owner, err := f.dep.UserClient().GetLoginUserByID(ctx, 2)
			require.NoError(t, err)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, 1, writer.GetClient().GroupPolicy.Query().Where(grouppolicy.GroupID(2)).CountX(txCtx))
			if mode == "new-node" {
				createDestination()
			}
			const server = "https://current-node.example.com"
			f.db.Node.UpdateOneID(destination.NodeID).SetServer(server).ExecX(ctx)
			ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, owner)
			fm := manager.NewFileManager(f.dep, owner)
			defer fm.Recycle()
			uri, err := fs.NewUriFromString("cloudreve://my/current-node.txt")
			require.NoError(t, err)
			req := &fs.UploadRequest{Props: &fs.UploadProps{
				Uri: uri, PreferredStoragePolicy: destination.ID, UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
			}}
			session, err := fm.PrepareUpload(txCtx, req)
			require.NoError(t, err)
			require.NoError(t, inventory.Commit(tx))
			// The accepted policy must remain usable by the native remote driver
			// after its owning transaction commits, before any provider I/O.
			handler, err := fm.GetStorageDriver(ctx, session.Policy)
			require.NoError(t, err)
			require.NotNil(t, handler)
			require.NotNil(t, session.Policy.Edges.Node)
			require.Equal(t, server, session.Policy.Edges.Node.Server)
		})
	}
}

func TestStorageUploadChecksCurrentActorInInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"disabled-actor", "demoted-administrator", "revoked-administrator-group", "administrator-inactive-owner"} {
		t.Run(mode, func(t *testing.T) {
			f := newStorageFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			f.assignPolicies(t, f.policies[0].ID)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, nil)
			actorID := 2
			root := "cloudreve://my/"
			if mode != "disabled-actor" {
				actorID = 1
				root = "cloudreve://" + hashid.EncodeUserID(f.dep.HashIDEncoder(), 2) + "@my/"
				f.loginAs(t, "storage-admin@example.com", f.adminPassword)
			}
			actor := f.db.User.Query().Where(user.ID(actorID)).WithGroup().OnlyX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, user.StatusActive, writer.GetClient().User.GetX(txCtx, 2).Status)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
			ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
			fm := manager.NewFileManager(f.dep, actor)
			defer fm.Recycle()
			rootURI, err := fs.NewUriFromString(root)
			require.NoError(t, err)
			_, err = fm.Get(txCtx, rootURI)
			require.NoError(t, err)
			changedID := 2
			switch mode {
			case "demoted-administrator":
				changedID = 1
				f.db.User.UpdateOneID(1).SetGroupUsers(2).ExecX(ctx)
			case "revoked-administrator-group":
				changedID = 1
				group := f.db.Group.GetX(ctx, 1)
				group.Permissions = f.db.Group.GetX(ctx, 2).Permissions
				_, err := f.dep.GroupClient().UpsertWithPolicies(ctx, group, nil)
				require.NoError(t, err)
			default:
				f.db.User.UpdateOneID(2).SetStatus(user.StatusManualBanned).ExecX(ctx)
			}
			stamp := f.db.User.GetX(ctx, changedID).UpdatedAt
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					m := mutation.(*ent.UserMutation)
					if added, ok := m.AddedStorage(); ok && added == 0 {
						// Exercise an unchanged lock at native timestamp precision.
						m.SetUpdatedAt(stamp)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			payload := []byte("active administrators retain native access to inactive owners")
			if mode != "administrator-inactive-owner" {
				payload = nil
			}
			uri := rootURI.Join("current-actor.txt")
			req := &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(payload)), Props: &fs.UploadProps{
				Uri: uri, Size: int64(len(payload)), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
			}}
			session, err := fm.PrepareUpload(txCtx, req)
			if mode != "administrator-inactive-owner" {
				require.ErrorIs(t, err, dbfs.ErrPermissionDenied)
				require.NoError(t, inventory.Commit(tx))
				require.Zero(t, f.db.User.GetX(ctx, 2).Storage)
				require.Zero(t, f.db.File.Query().Where(file.Name(uri.Name())).CountX(ctx))
				require.Zero(t, f.db.Entity.Query().CountX(ctx))
				f.assertObjectCounts(t, 0, 0)
				return
			}
			require.NoError(t, err)
			require.NoError(t, inventory.Commit(tx))
			require.NoError(t, fm.Upload(ctx, req, session.Policy, session))
			_, err = fm.CompleteUpload(ctx, session)
			require.NoError(t, err)
			require.Equal(t, payload, f.readFile(t, uri.String()))
		})
	}
}

func TestWritableShareUploadChecksCurrentOwnerInInheritedSnapshot(t *testing.T) {
	for _, mode := range []string{"collaborator", "administrator", "anonymous"} {
		t.Run(mode, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			const existing = "cloudreve://my/inherited-share/existing.txt"
			payload := []byte("retained share content")
			f.upload(t, existing, payload, nil)
			_, root := f.createWritableShare(t, "cloudreve://my/inherited-share", map[string]any{"everyone": "Lw==", "anonymous": "BA=="})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			actorID := 0
			switch mode {
			case "collaborator":
				visitor, _ := f.createWritableVisitor(t, 2)
				actorID = visitor.ID
			case "administrator":
				actorID = 1
			}
			actor, err := f.dep.UserClient().GetLoginUserByID(ctx, actorID)
			require.NoError(t, err)
			beforeFiles := f.db.File.Query().CountX(ctx)
			beforeEntities := f.db.Entity.Query().CountX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, user.StatusActive, writer.GetClient().User.GetX(txCtx, 2).Status)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
			fm := manager.NewFileManager(f.dep, actor)
			defer fm.Recycle()
			rootURI, err := fs.NewUriFromString(root)
			require.NoError(t, err)
			_, err = fm.Get(txCtx, rootURI)
			require.NoError(t, err)
			f.db.User.UpdateOneID(2).SetStatus(user.StatusManualBanned).ExecX(ctx)
			stamp := f.db.User.GetX(ctx, 2).UpdatedAt
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					m := mutation.(*ent.UserMutation)
					if added, ok := m.AddedStorage(); ok && added == 0 {
						// Exercise an unchanged lock at native timestamp precision.
						m.SetUpdatedAt(stamp)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			req := &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(nil)), Props: &fs.UploadProps{
				Uri: rootURI.Join("blocked.txt"), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
			}}
			_, err = fm.PrepareUpload(txCtx, req)
			require.ErrorIs(t, err, dbfs.ErrPermissionDenied)
			require.NoError(t, inventory.Commit(tx))
			require.Equal(t, beforeFiles, f.db.File.Query().CountX(ctx))
			require.Equal(t, beforeEntities, f.db.Entity.Query().CountX(ctx))
			require.EqualValues(t, len(payload), f.db.User.GetX(ctx, 2).Storage)
			f.assertObjectCounts(t, 1, 0)
			f.db.User.UpdateOneID(2).SetStatus(user.StatusActive).ExecX(ctx)
			require.Equal(t, payload, f.readFile(t, existing))
		})
	}
}

func TestWritableShareUploadRevalidatesCurrentPermissionsInInheritedSnapshot(t *testing.T) {
	for _, change := range []string{"link-permission", "deleted-link", "descendant-acl"} {
		t.Run(change, func(t *testing.T) {
			f := newWritableShareFixture(t)
			if f.database.Type != "mysql" {
				t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
			}
			const existing = "cloudreve://my/current-share/sub/existing.txt"
			payload := []byte("retained share content")
			f.upload(t, existing, payload, nil)
			id, shared := f.createWritableShare(t, "cloudreve://my/current-share", map[string]any{"everyone": "Lw=="})
			visitor, _ := f.createWritableVisitor(t, 2)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			actor, err := f.dep.UserClient().GetLoginUserByID(ctx, visitor.ID)
			require.NoError(t, err)
			beforeFiles := f.db.File.Query().CountX(ctx)
			beforeEntities := f.db.Entity.Query().CountX(ctx)
			writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
			require.NoError(t, err)
			defer inventory.Rollback(tx)
			require.Equal(t, user.StatusActive, writer.GetClient().User.GetX(txCtx, 2).Status)
			txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
			fm := manager.NewFileManager(f.dep, actor)
			defer fm.Recycle()
			rootURI, err := fs.NewUriFromString(shared + "/sub")
			require.NoError(t, err)
			_, err = fm.Get(txCtx, rootURI)
			require.NoError(t, err)
			switch change {
			case "link-permission":
				f.request(t, http.MethodPost, "/api/v4/share/"+id, map[string]any{
					"uri": "cloudreve://my/current-share", "permissions": map[string]any{"everyone": "IQ=="},
				}, nil)
			case "deleted-link":
				f.request(t, http.MethodDelete, "/api/v4/share/"+id, nil, nil)
			case "descendant-acl":
				f.request(t, http.MethodPost, "/api/v4/file/permission", map[string]any{
					"uris": []string{"cloudreve://my/current-share/sub"}, "setting": map[string]any{"everyone": "AA=="},
				}, nil)
			}
			stamp := f.db.User.GetX(ctx, 2).UpdatedAt
			f.db.User.Use(func(next ent.Mutator) ent.Mutator {
				return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
					m := mutation.(*ent.UserMutation)
					if added, ok := m.AddedStorage(); ok && added == 0 {
						m.SetUpdatedAt(stamp)
					}
					return next.Mutate(ctx, mutation)
				})
			})
			req := &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(nil)), Props: &fs.UploadProps{
				Uri: rootURI.Join("blocked.txt"), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
			}}
			_, err = fm.PrepareUpload(txCtx, req)
			var appErr serializer.AppError
			require.ErrorAs(t, err, &appErr)
			if change == "descendant-acl" {
				require.Equal(t, serializer.CodeConflict, appErr.Code)
			} else {
				require.Equal(t, serializer.CodeNoPermissionErr, appErr.Code)
			}
			require.NoError(t, inventory.Commit(tx))
			require.Equal(t, beforeFiles, f.db.File.Query().CountX(ctx))
			require.Equal(t, beforeEntities, f.db.Entity.Query().CountX(ctx))
			require.EqualValues(t, len(payload), f.db.User.GetX(ctx, 2).Storage)
			f.assertObjectCounts(t, 1, 0)
			require.Equal(t, payload, f.readFile(t, existing))
		})
	}
}

func TestWritableShareUploadUsesNewLinkInInheritedSnapshot(t *testing.T) {
	f := newWritableShareFixture(t)
	if f.database.Type != "mysql" {
		t.Skip("MySQL repeatable-read current writes differ from snapshot reads")
	}
	const folder = "cloudreve://my/new-shared-link"
	f.upload(t, folder+"/existing.txt", []byte("existing"), nil)
	visitor, _ := f.createWritableVisitor(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	actor, err := f.dep.UserClient().GetLoginUserByID(ctx, visitor.ID)
	require.NoError(t, err)
	writer, tx, txCtx, err := inventory.WithTx(ctx, f.dep.FileClient())
	require.NoError(t, err)
	defer inventory.Rollback(tx)
	require.Equal(t, user.StatusActive, writer.GetClient().User.GetX(txCtx, 2).Status)
	_, shared := f.createWritableShare(t, folder, map[string]any{"everyone": "Lw=="})
	txCtx = context.WithValue(txCtx, inventory.UserCtx{}, actor)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, actor)
	fm := manager.NewFileManager(f.dep, actor)
	defer fm.Recycle()
	root, err := fs.NewUriFromString(shared)
	require.NoError(t, err)
	payload := []byte("link created after the caller's snapshot")
	req := &fs.UploadRequest{File: io.NopCloser(bytes.NewReader(payload)), Props: &fs.UploadProps{
		Uri: root.Join("new.txt"), Size: int64(len(payload)), UploadSessionID: uuid.Must(uuid.NewV4()).String(), ExpireAt: time.Now().Add(time.Minute),
	}}
	session, err := fm.PrepareUpload(txCtx, req)
	require.NoError(t, err)
	require.NoError(t, inventory.Commit(tx))
	require.NoError(t, fm.Upload(ctx, req, session.Policy, session))
	_, err = fm.CompleteUpload(ctx, session)
	require.NoError(t, err)
	require.Equal(t, payload, f.readFile(t, folder+"/new.txt"))
	require.EqualValues(t, len("existing")+len(payload), f.db.User.GetX(ctx, 2).Storage)
	f.assertObjectCounts(t, 2, 0)
}

func TestStorageExplicitSecondPolicyUsesItsOwnRestrictionsAndLocation(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[0].ID, f.policies[1].ID)
	settings := *f.policies[0].Settings
	settings.FileType = []string{"bin"}
	_, err := f.db.StoragePolicy.UpdateOneID(f.policies[0].ID).SetMaxSize(1).SetSettings(&settings).Save(context.Background())
	require.NoError(t, err)
	uri := "cloudreve://my/explicit.txt"
	payload := []byte("selected B has no restrictive size or suffix from default A")
	id := hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)
	session := f.upload(t, uri, payload, id)
	require.Equal(t, id, session.StoragePolicy.ID)
	require.Equal(t, payload, f.readFile(t, uri))
	var info explorer.FileResponse
	f.request(t, http.MethodGet, "/api/v4/file/info?extended=true&uri="+url.QueryEscape(uri), nil, &info)
	require.Equal(t, id, info.ExtendedInfo.StoragePolicy.ID)
	require.Len(t, info.ExtendedInfo.Entities, 1)
	require.Equal(t, id, info.ExtendedInfo.Entities[0].StoragePolicy.ID)
	for index, policy := range f.policies {
		objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
		require.NoError(t, err)
		if index == 1 {
			require.Len(t, objects.Contents, 1)
		} else {
			require.Empty(t, objects.Contents)
		}
	}
}

func TestStorageUnauthorizedUploadsLeaveNoObjectsPlaceholdersOrQuota(t *testing.T) {
	f := newStorageFixture(t)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.Empty(t, listing.Files)
	for _, id := range []any{"invalid!", hashid.EncodePolicyID(f.dep.HashIDEncoder(), 999999), hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID)} {
		body := map[string]any{"uri": "cloudreve://my/retry.txt", "size": 5, "policy_id": id, "import": true, "import_from": "forged", "thumbnail": true, "bypass": true}
		w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/file/upload", body, nil, f.token)
		var result struct {
			Code int `json:"code"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		require.NotZero(t, result.Code)
		f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
		require.Empty(t, listing.Files)
		var capacity fs.Capacity
		f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &capacity)
		require.Zero(t, capacity.Used)
		for _, policy := range f.policies {
			objects, err := f.s3.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(policy.BucketName)})
			require.NoError(t, err)
			require.Empty(t, objects.Contents)
		}
	}
	w := openIDRequest(t, f.router, http.MethodPost, "/api/v4/workflow/import", map[string]any{"policy_id": f.policies[1].ID}, nil, f.token)
	var forbidden struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &forbidden))
	require.Equal(t, serializer.CodeNoPermissionErr, forbidden.Code)
	f.upload(t, "cloudreve://my/retry.txt", []byte("valid retry uses the same path without retained lock"), hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[0].ID))
}

func TestStorageAutomaticUploadOmittedNullAndEmptyUseCurrentDefault(t *testing.T) {
	f := newStorageFixture(t)
	f.assignPolicies(t, f.policies[1].ID, f.policies[0].ID)
	for i, selection := range []any{nil, "", storageNullPolicy{}} {
		var id any = selection
		if _, ok := selection.(storageNullPolicy); ok {
			id = json.RawMessage("null")
		}
		uri := fmt.Sprintf("cloudreve://my/automatic-%d.txt", i)
		session := f.upload(t, uri, []byte("automatic selection contract"), id)
		require.Equal(t, hashid.EncodePolicyID(f.dep.HashIDEncoder(), f.policies[1].ID), session.StoragePolicy.ID)
	}
	// Removing grants cannot fall back to the obsolete default column.
	_, err := f.db.GroupPolicy.Delete().Where(grouppolicy.GroupID(2)).Exec(context.Background())
	require.NoError(t, err)
	var available []explorer.StoragePolicy
	f.request(t, http.MethodGet, "/api/v4/user/setting/policies", nil, &available)
	require.Empty(t, available)
	var before fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &before)
	w := openIDRequest(t, f.router, http.MethodPut, "/api/v4/file/upload", map[string]any{"uri": "cloudreve://my/forbidden.txt", "size": 10}, nil, f.token)
	var rejected struct {
		Code int `json:"code"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rejected))
	require.NotZero(t, rejected.Code)
	var after fs.Capacity
	f.request(t, http.MethodGet, "/api/v4/user/capacity", nil, &after)
	require.Equal(t, before.Used, after.Used)
	var listing explorer.ListResponse
	f.request(t, http.MethodGet, "/api/v4/file?uri="+url.QueryEscape("cloudreve://my/"), nil, &listing)
	require.Len(t, listing.Files, 3)
}

type storageNullPolicy struct{}
