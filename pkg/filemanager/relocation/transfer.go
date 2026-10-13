package relocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/group"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	entpolicy "github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager/entitysource"
	"github.com/cloudreve/Cloudreve/v4/pkg/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/gofrs/uuid"
)

var (
	ErrLeaseBusy = errors.New("migration item is owned by another worker")
	ErrLeaseLost = errors.New("migration item lease was lost")
	ErrConflict  = errors.New("migration source changed before commit")
)

const leaseDuration = 30 * time.Second

// AdvanceSingle crosses one durable boundary per native queue iteration. The
// journal, rather than stale Task private state, decides what remains to do.
func AdvanceSingle(ctx context.Context, dep dependency.Dep, taskID, ownerID int, sources []string, destinationID int) (bool, error) {
	db := dep.DBClient()
	items, err := db.RelocationItem.Query().Where(relocationitem.TaskID(taskID)).All(ctx)
	if err != nil {
		return false, errors.New("failed to load migration journal")
	}
	if len(items) == 0 {
		plan, err := PlanSingle(ctx, dep, ownerID, sources, destinationID)
		if err != nil {
			return false, errors.New("migration planning failed")
		}
		if plan.Entity.StoragePolicyEntities == destinationID {
			if err := RecordNoop(ctx, db, taskID, plan); err != nil {
				return false, errors.New("failed to persist migration plan")
			}
			return true, nil
		}
		return false, recordSinglePlan(ctx, dep, taskID, plan)
	}
	if len(items) != 1 || items[0].OwnerID != ownerID || items[0].DestinationPolicyID != destinationID || len(sources) != 1 {
		return false, errors.New("invalid migration journal")
	}
	item := items[0]
	if item.State == relocationitem.StateCommitted || item.State == relocationitem.StateNoop {
		return true, nil
	}
	if item.State == relocationitem.StateFailed {
		return false, errors.New("migration item previously failed")
	}
	item, err = claim(ctx, db, item)
	if err != nil {
		return false, err
	}
	uri, err := fs.NewUriFromString(sources[0])
	if err != nil {
		return false, errors.New("invalid migration source")
	}
	owner, err := inventory.NewUserClient(db).GetActiveByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	if err != nil {
		return false, failItem(ctx, db, item, errors.New("migration owner is unavailable"))
	}
	fm := manager.NewFileManager(dep, owner)
	defer fm.Recycle()
	ls, err := fm.Lock(ctx, leaseDuration, owner, true, fs.LockApp(fs.ApplicationRelocate), uri, "")
	if err != nil {
		return false, failItem(ctx, db, item, errors.New("failed to lock migration source"))
	}
	defer fm.Unlock(context.WithoutCancel(ctx), ls.LastToken())
	workCtx, cancel := context.WithCancel(ctx)
	stop := maintainLease(workCtx, cancel, db, item, fm, ls.LastToken())
	defer stop()
	if item.State == relocationitem.StateVerified {
		err = commitSingle(workCtx, dep, fm, item)
		if err != nil {
			return false, failItem(ctx, db, item, err)
		}
		return true, nil
	}
	err = copySingle(workCtx, dep, fm, item, uri)
	if err != nil {
		return false, failItem(ctx, db, item, err)
	}
	return false, nil
}

func authorizedOwner(ctx context.Context, db *ent.Client, ownerID, destinationID int) (*ent.User, error) {
	owner, err := inventory.NewUserClient(db).GetActiveByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	if err != nil || owner.Edges.Group == nil || owner.Edges.Group.Permissions == nil || !owner.Edges.Group.Permissions.Enabled(int(types.GroupPermissionRelocate)) {
		return nil, errors.New("migration authorization is unavailable")
	}
	_, err = storagepolicy.New(inventory.NewUserClient(db), inventory.NewStoragePolicyClient(db, nil)).Select(ctx, ownerID, destinationID, 0)
	if err != nil {
		return nil, errors.New("migration destination is unavailable")
	}
	return owner, nil
}

// The owner lifecycle/quota lock is always first. The net quota change is zero.
func lockOwner(ctx context.Context, db *ent.Client, ownerID, destinationID int) error {
	n, err := db.User.Update().Where(user.ID(ownerID), user.StatusEQ(user.StatusActive)).AddStorage(0).Save(ctx)
	if err != nil || n != 1 {
		return errors.New("migration owner is unavailable")
	}
	owner, err := db.User.Get(ctx, ownerID)
	if err != nil {
		return errors.New("failed to load migration owner")
	}
	if _, err := db.Group.Update().Where(group.ID(owner.GroupUsers)).AddMaxStorage(0).Save(ctx); err != nil {
		return errors.New("failed to lock migration authorization")
	}
	_, err = authorizedOwner(ctx, db, ownerID, destinationID)
	return err
}

func lockPolicies(ctx context.Context, db *ent.Client, ids ...int) (map[int]*ent.StoragePolicy, error) {
	sort.Ints(ids)
	policies := make(map[int]*ent.StoragePolicy)
	for _, id := range ids {
		if policies[id] != nil {
			continue
		}
		p, err := inventory.LockStoragePolicy(ctx, db, id)
		if err != nil {
			return nil, errors.New("migration storage policy is unavailable")
		}
		policies[id] = p
	}
	return policies, nil
}

func recordSinglePlan(ctx context.Context, dep dependency.Dep, taskID int, plan *Plan) error {
	tx, err := dep.DBClient().Tx(ctx)
	if err != nil {
		return errors.New("failed to start migration plan transaction")
	}
	defer tx.Rollback()
	c := tx.Client()
	if err := lockOwner(ctx, c, plan.Owner.ID, plan.Destination.ID); err != nil {
		return err
	}
	policies, err := lockPolicies(ctx, c, plan.Entity.StoragePolicyEntities, plan.Destination.ID)
	if err != nil {
		return err
	}
	e := plan.Entity
	if err := lockSourceEntity(ctx, c, e.ID); err != nil {
		return errors.New("migration source lock did not match its snapshot")
	}
	current, err := c.Entity.Get(ctx, e.ID)
	if err != nil || current.UploadSessionID != nil || current.ReferenceCount != 1 || current.Source != e.Source || current.StoragePolicyEntities != e.StoragePolicyEntities || !current.UpdatedAt.Equal(e.UpdatedAt) {
		return errors.New("migration source changed during planning")
	}
	err = c.RelocationItem.Create().SetTaskID(taskID).SetOwnerID(plan.Owner.ID).SetSourceEntityID(e.ID).
		SetSourcePolicyID(e.StoragePolicyEntities).SetSourceKey(e.Source).SetSourceLocation(Location(policies[e.StoragePolicyEntities])).
		SetDestinationPolicyID(plan.Destination.ID).SetDestinationLocation(Location(policies[plan.Destination.ID])).
		SetSnapshot(&types.RelocationSnapshot{Type: e.Type, Size: e.Size, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, CreatedBy: e.CreatedBy, Props: e.Props}).SetReferences(plan.References).
		OnConflictColumns(relocationitem.FieldTaskID, relocationitem.FieldSourceEntityID).DoNothing().Exec(ctx)
	if err != nil {
		return errors.New("failed to persist migration plan")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("failed to commit migration plan")
	}
	return nil
}

func claim(ctx context.Context, db *ent.Client, item *ent.RelocationItem) (*ent.RelocationItem, error) {
	now := time.Now()
	n, err := db.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence),
		relocationitem.StateIn(relocationitem.StatePlanned, relocationitem.StateCopying, relocationitem.StateVerified),
		relocationitem.Or(relocationitem.LeaseUntilIsNil(), relocationitem.LeaseUntilLTE(now))).
		AddFence(1).SetLeaseOwner(uuid.Must(uuid.NewV4()).String()).SetLeaseUntil(now.Add(leaseDuration)).Save(ctx)
	if err != nil {
		return nil, errors.New("failed to claim migration item")
	}
	if n != 1 {
		return nil, ErrLeaseBusy
	}
	claimed, err := db.RelocationItem.Get(ctx, item.ID)
	if err != nil {
		return nil, errors.New("failed to load claimed migration item")
	}
	return claimed, nil
}

func maintainLease(ctx context.Context, cancel context.CancelFunc, db *ent.Client, item *ent.RelocationItem, fm manager.FileManager, token string) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(leaseDuration / 3)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := db.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.LeaseOwner(item.LeaseOwner), relocationitem.LeaseUntilGT(time.Now())).SetLeaseUntil(time.Now().Add(leaseDuration)).Save(ctx)
				if err != nil || n != 1 {
					cancel()
					return
				}
				if _, err := fm.Refresh(ctx, leaseDuration, token); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

func currentSource(ctx context.Context, db *ent.Client, item *ent.RelocationItem) (*ent.Entity, *ent.StoragePolicy, *ent.StoragePolicy, error) {
	if _, err := authorizedOwner(ctx, db, item.OwnerID, item.DestinationPolicyID); err != nil {
		return nil, nil, nil, err
	}
	source, err := db.Entity.Query().Where(entity.ID(item.SourceEntityID)).WithFile().Only(ctx)
	if err != nil || item.Snapshot == nil || source.UploadSessionID != nil || source.ReferenceCount != 1 || len(source.Edges.File) != 1 || len(item.References) != 1 {
		return nil, nil, nil, ErrConflict
	}
	f := source.Edges.File[0]
	ref := item.References[0]
	props, _ := json.Marshal(source.Props)
	snapshotProps, _ := json.Marshal(item.Snapshot.Props)
	if source.Type != item.Snapshot.Type || source.Size != item.Snapshot.Size || source.CreatedBy != item.Snapshot.CreatedBy || !source.CreatedAt.Equal(item.Snapshot.CreatedAt) || source.Source != item.SourceKey || source.StoragePolicyEntities != item.SourcePolicyID || !source.UpdatedAt.Equal(item.Snapshot.UpdatedAt) || string(props) != string(snapshotProps) || f.ID != ref.FileID || f.OwnerID != item.OwnerID || f.PrimaryEntity != ref.PrimaryEntityID || !f.UpdatedAt.Equal(ref.UpdatedAt) {
		return nil, nil, nil, ErrConflict
	}
	load := func(id int) (*ent.StoragePolicy, error) {
		return db.StoragePolicy.Query().Where(entpolicy.ID(id)).WithNode().Only(ctx)
	}
	a, err := load(item.SourcePolicyID)
	if err != nil {
		return nil, nil, nil, errors.New("migration source storage is unavailable")
	}
	b, err := load(item.DestinationPolicyID)
	if err != nil {
		return nil, nil, nil, errors.New("migration destination storage is unavailable")
	}
	if Location(a) != item.SourceLocation || Location(b) != item.DestinationLocation {
		return nil, nil, nil, errors.New("migration storage location changed")
	}
	return source, a, b, nil
}

type digestReader struct {
	io.Reader
	hash hash.Hash
	size int64
}

func (r *digestReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.size += int64(n)
	r.hash.Write(p[:n])
	return n, err
}

func rawSource(ctx context.Context, fm manager.FileManager, entity *ent.Entity, policy *ent.StoragePolicy) (entitysource.EntitySource, error) {
	r, err := fm.GetEntitySource(ctx, 0, fs.WithEntity(fs.NewEntity(entity)), fs.WithPolicy(policy))
	if err == nil {
		r.Apply(entitysource.WithDisableCryptor())
	}
	return r, err
}

func copySingle(ctx context.Context, dep dependency.Dep, fm manager.FileManager, item *ent.RelocationItem, uri *fs.URI) error {
	db := dep.DBClient()
	source, a, b, err := currentSource(ctx, db, item)
	if err != nil {
		return err
	}
	dir := util.ReplaceMagicVar(filepath.ToSlash(b.DirNameRule), fs.Separator, true, false, time.Now(), item.OwnerID, uri.Name(), uri.Dir(), "")
	key := path.Join(dir, ".cloudreve-relocation", fmt.Sprint(item.ID), fmt.Sprint(item.Fence), uuid.Must(uuid.NewV4()).String())
	tx, err := db.Tx(ctx)
	if err != nil {
		return errors.New("failed to begin migration attempt")
	}
	defer tx.Rollback()
	attempt, err := tx.RelocationAttempt.Create().SetItemID(item.ID).SetFence(item.Fence).SetTargetKey(key).Save(ctx)
	if err != nil {
		return errors.New("failed to persist migration attempt")
	}
	n, err := tx.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.LeaseOwner(item.LeaseOwner), relocationitem.LeaseUntilGT(time.Now())).SetActiveAttemptID(attempt.ID).SetState(relocationitem.StateCopying).SetSourceReadFinished(false).Save(ctx)
	if err != nil || n != 1 {
		return ErrLeaseLost
	}
	if err := tx.Commit(); err != nil {
		return errors.New("failed to commit migration attempt")
	}
	r, err := rawSource(ctx, fm, source, a)
	if err != nil {
		return errors.New("failed to open migration source")
	}
	defer r.Close()
	d, err := fm.GetStorageDriver(ctx, b)
	if err != nil {
		return errors.New("failed to open migration destination")
	}
	if err := db.RelocationAttempt.UpdateOneID(attempt.ID).SetIoState(relocationattempt.IoStateInFlight).Exec(ctx); err != nil {
		return errors.New("failed to record migration I/O")
	}
	digest := &digestReader{Reader: r, hash: sha256.New()}
	err = d.Put(ctx, &fs.UploadRequest{File: io.NopCloser(digest), Props: &fs.UploadProps{Uri: uri, SavePath: key, Size: source.Size}})
	ioState := relocationattempt.IoStateEnded
	if err != nil {
		ioState = relocationattempt.IoStateUnknown
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	recordErr := db.RelocationAttempt.UpdateOneID(attempt.ID).SetIoState(ioState).Exec(recordCtx)
	cancel()
	if recordErr != nil {
		return errors.New("failed to record migration I/O result")
	}
	if err != nil {
		return errors.New("migration copy failed")
	}
	if digest.size != source.Size {
		return errors.New("migration source length mismatch")
	}
	var extra [1]byte
	if n, err := r.Read(extra[:]); n != 0 || (err != nil && err != io.EOF) {
		return errors.New("migration source length mismatch")
	}
	attempt.VerifiedDigest = hex.EncodeToString(digest.hash.Sum(nil))
	attempt.VerifiedSize = digest.size
	if err := verifyTarget(ctx, fm, source, b, attempt); err != nil {
		return err
	}
	tx2, err := db.Tx(ctx)
	if err != nil {
		return errors.New("failed to persist migration verification")
	}
	defer tx2.Rollback()
	n, err = tx2.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.LeaseOwner(item.LeaseOwner), relocationitem.LeaseUntilGT(time.Now()), relocationitem.ActiveAttemptID(attempt.ID)).SetState(relocationitem.StateVerified).SetSourceReadFinished(true).SetLeaseOwner("").ClearLeaseUntil().Save(ctx)
	if err != nil || n != 1 {
		return ErrLeaseLost
	}
	if err := tx2.RelocationAttempt.UpdateOneID(attempt.ID).SetVerified(true).SetVerifiedSize(attempt.VerifiedSize).SetVerifiedDigest(attempt.VerifiedDigest).Exec(ctx); err != nil {
		return errors.New("failed to persist migration verification")
	}
	if err := tx2.Commit(); err != nil {
		return errors.New("failed to commit migration verification")
	}
	return nil
}

func verifyTarget(ctx context.Context, fm manager.FileManager, source *ent.Entity, policy *ent.StoragePolicy, attempt *ent.RelocationAttempt) error {
	target := *source
	target.Source = attempt.TargetKey
	target.StoragePolicyEntities = policy.ID
	r, err := rawSource(ctx, fm, &target, policy)
	if err != nil {
		return errors.New("failed to read migration target")
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, source.Size+1))
	if err != nil || n != source.Size || n != attempt.VerifiedSize || hex.EncodeToString(h.Sum(nil)) != attempt.VerifiedDigest {
		return errors.New("migration target verification failed")
	}
	return nil
}

func commitSingle(ctx context.Context, dep dependency.Dep, fm manager.FileManager, item *ent.RelocationItem) error {
	db := dep.DBClient()
	source, _, b, err := currentSource(ctx, db, item)
	if err != nil {
		return err
	}
	attempt, err := db.RelocationAttempt.Get(ctx, item.ActiveAttemptID)
	if err != nil || !attempt.Verified || attempt.IoState != relocationattempt.IoStateEnded || attempt.ItemID != item.ID {
		return errors.New("migration target has no trusted verification")
	}
	if err := verifyTarget(ctx, fm, source, b, attempt); err != nil {
		return err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return errors.New("failed to start migration commit")
	}
	defer tx.Rollback()
	c := tx.Client()
	if err := lockOwner(ctx, c, item.OwnerID, item.DestinationPolicyID); err != nil {
		return err
	}
	if _, err := lockPolicies(ctx, c, item.SourcePolicyID, item.DestinationPolicyID); err != nil {
		return err
	}
	if err := lockSourceEntity(ctx, c, item.SourceEntityID); err != nil {
		return ErrConflict
	}
	if _, _, _, err := currentSource(ctx, c, item); err != nil {
		return err
	}
	n, err := c.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.LeaseOwner(item.LeaseOwner), relocationitem.LeaseUntilGT(time.Now()), relocationitem.StateEQ(relocationitem.StateVerified), relocationitem.ActiveAttemptID(attempt.ID)).SetState(relocationitem.StateCommitted).SetTargetEntityID(source.ID).SetSourceReadFinished(true).SetLeaseOwner("").ClearLeaseUntil().Save(ctx)
	if err != nil || n != 1 {
		return ErrLeaseLost
	}
	if err := c.Entity.UpdateOneID(source.ID).SetSource(attempt.TargetKey).SetStoragePolicyEntities(item.DestinationPolicyID).SetUpdatedAt(item.Snapshot.UpdatedAt).Exec(ctx); err != nil {
		return errors.New("failed to switch migration entity")
	}
	if err := c.RelocationAttempt.UpdateOneID(attempt.ID).SetCleanup(relocationattempt.CleanupRetained).Exec(ctx); err != nil {
		return errors.New("failed to retain committed migration target")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("failed to commit migration references")
	}
	return nil
}

// Called only inside a transaction with a server-owned integer identity. This
// portable no-op write locks the row without CommonMixin changing updated_at.
// Read the snapshot again after locking; SQL timestamp string equality is not
// portable across SQLite driver encodings. MySQL may report zero changed rows.
func lockSourceEntity(ctx context.Context, db *ent.Client, id int) error {
	if id <= 0 {
		return ErrConflict
	}
	_, err := db.ExecContext(ctx, "UPDATE entities SET reference_count = reference_count WHERE id = "+strconv.Itoa(id))
	return err
}

func failItem(ctx context.Context, db *ent.Client, item *ent.RelocationItem, cause error) error {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = db.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.LeaseOwner(item.LeaseOwner), relocationitem.LeaseUntilGT(time.Now()), relocationitem.StateNotIn(relocationitem.StateCommitted, relocationitem.StateNoop)).SetState(relocationitem.StateFailed).SetError(cause.Error()).SetLeaseOwner("").ClearLeaseUntil().Save(recordCtx)
	return cause
}
