package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	"github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/grouppolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/policyloadbalance"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationattempt"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/schema"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

var (
	ErrStoragePolicyInUse   = errors.New("storage policy has file, upload or migration dependencies")
	ErrStoragePolicyGranted = errors.New("storage policy is granted to an active group")
)

// LockStoragePolicy must run inside the caller's transaction. Uploads acquire
// the owner quota lock first; administrators acquire only this policy lock.
// A real no-op write supplies a lifecycle lock on every supported dialect.
func LockStoragePolicy(ctx context.Context, c *ent.Client, id int) (*ent.StoragePolicy, error) {
	_, err := c.StoragePolicy.UpdateOneID(id).Where(storagepolicy.DeletedAtIsNil()).AddMaxSize(0).Save(ctx)
	// Ent's unchanged-row existence fallback can miss newly committed rows.
	// The following current read decides existence while retaining this lock.
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	return c.StoragePolicy.Query().Where(storagepolicy.ID(id), storagepolicy.DeletedAtIsNil(), storageLifecycleRead).
		WithNode(func(q *ent.NodeQuery) { q.Where(CurrentPermissionRead) }).Only(ctx)
}

// LockActiveStorageOwner must run inside the caller's transaction. Ent's
// unchanged-row fallback may use an older snapshot, so verify current status
// while holding the same owner lock used by storage writes.
func LockActiveStorageOwner(ctx context.Context, c *ent.Client, id int) error {
	if _, err := c.User.UpdateOneID(id).Where(user.StatusEQ(user.StatusActive)).AddStorage(0).Save(ctx); err != nil && !ent.IsNotFound(err) {
		return err
	}
	_, err := c.User.Query().Where(user.ID(id), user.StatusEQ(user.StatusActive), storageLifecycleRead).Only(ctx)
	return err
}

// lockStoragePolicyReferences must precede entity locks in the caller's copy
// transaction. Retired preferences still have foreign keys; this is not a grant.
func lockStoragePolicyReferences(ctx context.Context, c *ent.Client, ids ...int) error {
	unique := make(map[int]bool, len(ids))
	for _, id := range ids {
		if id > 0 {
			unique[id] = true
		}
	}
	ordered := make([]int, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	sort.Ints(ordered)
	for _, id := range ordered {
		_, err := c.StoragePolicy.Query().Where(storagepolicy.ID(id), CurrentPermissionRead).
			Select(storagepolicy.FieldID).Only(schema.SkipSoftDelete(ctx))
		if err != nil {
			return err
		}
	}
	return nil
}

// LockCopyReferences locks the complete policy and entity unions in that order,
// numerically within each union. Owner locks must already fence selected files.
// Planning includes pending and newly committed references without early locks.
func LockCopyReferences(ctx context.Context, c *ent.Client, fileIDs ...int) error {
	policyIDs, entityIDs := make(map[int]bool), make(map[int]bool)
	committed := CommittedMetadataClient(ctx)
	// Keep reference planning below the SQL parameter limits on all dialects.
	for start := 0; start < len(fileIDs); start += 500 {
		batch := fileIDs[start:min(start+500, len(fileIDs))]
		serverDB := false
		read := func(client *ent.Client) error {
			files, err := client.File.Query().Where(file.IDIn(batch...), func(s *sql.Selector) {
				serverDB = s.Dialect() != dialect.SQLite
			}).Select(file.FieldID, file.FieldStoragePolicyFiles).All(ctx)
			if err != nil {
				return err
			}
			for _, f := range files {
				policyIDs[f.StoragePolicyFiles] = true
			}
			entities, err := client.Entity.Query().Where(entity.HasFileWith(file.IDIn(batch...))).
				Select(entity.FieldID, entity.FieldStoragePolicyEntities).All(ctx)
			if err != nil {
				return err
			}
			for _, e := range entities {
				entityIDs[e.ID] = true
				policyIDs[e.StoragePolicyEntities] = true
			}
			return nil
		}
		if err := read(c); err != nil {
			return err
		}
		// The inherited view retains pending writes; committed metadata supplies
		// references added after its snapshot without early entity locks. SQLite
		// must keep its transaction's sole connection.
		if serverDB && committed != nil {
			if err := read(committed); err != nil {
				return err
			}
		}
	}
	policies := make([]int, 0, len(policyIDs))
	for id := range policyIDs {
		policies = append(policies, id)
	}
	if err := lockStoragePolicyReferences(ctx, c, policies...); err != nil {
		return err
	}
	entities := make([]int, 0, len(entityIDs))
	for id := range entityIDs {
		entities = append(entities, id)
	}
	sort.Ints(entities)
	for _, id := range entities {
		if _, err := c.ExecContext(ctx, "UPDATE entities SET reference_count = reference_count WHERE id = "+strconv.Itoa(id)); err != nil {
			return err
		}
	}
	// Distinct Entity rows can alias the same physical objects. Lock their
	// complete key union before any layer writes, after the entity union.
	type objectReference struct {
		policy *ent.StoragePolicy
		source string
	}
	objects := make(map[string]objectReference)
	for start := 0; start < len(entities); start += 500 {
		batch := entities[start:min(start+500, len(entities))]
		current, err := c.Entity.Query().Where(entity.IDIn(batch...), CurrentPermissionRead).
			Select(entity.FieldID, entity.FieldStoragePolicyEntities, entity.FieldSource).
			WithStoragePolicy(func(q *ent.StoragePolicyQuery) { q.Where(CurrentPermissionRead) }).All(ctx)
		if err != nil {
			return err
		}
		for _, e := range current {
			policy := e.Edges.StoragePolicy
			if policy == nil {
				return fmt.Errorf("copy entity storage policy is unavailable")
			}
			objects[StorageObjectKey(policy, e.Source)] = objectReference{policy, e.Source}
		}
	}
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ref := objects[key]
		// Planning may include obsolete snapshot associations. Only the
		// current source associations in Copy decide whether retirement denies it.
		if _, err := LockStorageObject(ctx, c, ref.policy, ref.source); err != nil {
			return err
		}
	}
	return nil
}

// LockCopyTreeReferences precedes recursive current reads, whose InnoDB gap
// locks must not be held while waiting for another copy's shared entities.
// Owner locks already fence the selected roots; metadata never authorizes them.
func LockCopyTreeReferences(ctx context.Context, c *ent.Client, roots []*ent.File, destinationID int) error {
	ids := map[int]bool{destinationID: true}
	folders := make(map[int]bool)
	parents := make([]int, 0, len(roots))
	for _, root := range roots {
		ids[root.ID] = true
		if root.Type == int(types.FileTypeFolder) && !root.IsSymbolic && !folders[root.ID] {
			folders[root.ID] = true
			parents = append(parents, root.ID)
		}
	}
	committed := CommittedMetadataClient(ctx)
	serverDB := false
	for len(parents) > 0 {
		next := make([]int, 0)
		for start := 0; start < len(parents); start += 500 {
			batch := parents[start:min(start+500, len(parents))]
			read := func(client *ent.Client) error {
				cursor := 0
				for {
					// These views conservatively include obsolete references.
					// Only native current traversal can enforce MaxWalkedFiles;
					// metadata planning keeps each query bounded instead.
					pageSize := 500
					children, err := client.File.Query().Where(file.FileChildrenIn(batch...), file.IDGT(cursor), func(s *sql.Selector) {
						serverDB = s.Dialect() != dialect.SQLite
					}).Order(ent.Asc(file.FieldID)).Limit(pageSize).
						Select(file.FieldID, file.FieldType, file.FieldIsSymbolic).All(ctx)
					if err != nil {
						return err
					}
					for _, child := range children {
						cursor = child.ID
						ids[child.ID] = true
						if child.Type == int(types.FileTypeFolder) && !child.IsSymbolic && !folders[child.ID] {
							folders[child.ID] = true
							next = append(next, child.ID)
						}
					}
					if len(children) < pageSize {
						break
					}
				}
				return nil
			}
			if err := read(c); err != nil {
				return err
			}
			// A pending move can join a committed subtree to a snapshot root.
			// Expand the SAME frontier in both views to discover that closure.
			if serverDB && committed != nil {
				if err := read(committed); err != nil {
					return err
				}
			}
		}
		parents = next
	}
	files := make([]int, 0, len(ids))
	for id := range ids {
		files = append(files, id)
	}
	return LockCopyReferences(ctx, c, files...)
}

// StoragePolicyGranted revalidates a logical or concrete destination after the
// caller locks its owner and chosen concrete policy, in that order. Both lookups
// must observe current rows, including inside an inherited repeatable-read
// transaction. Native pool and group writes remove obsolete bindings atomically.
// Do not lock other policy or group rows here: their writers acquire those locks
// before editing bindings, and reversing that order can deadlock.
func StoragePolicyGranted(ctx context.Context, c *ent.Client, ownerID, policyID, poolID int) (bool, error) {
	owner, err := c.User.Query().Where(user.ID(ownerID), user.DeletedAtIsNil(), storageLifecycleRead).Only(ctx)
	if err != nil {
		return false, err
	}
	return c.GroupPolicy.Query().Where(
		grouppolicy.GroupID(owner.GroupUsers),
		func(s *sql.Selector) {
			b := sql.Dialect(s.Dialect())
			members := b.Table(policyloadbalance.Table)
			pools := b.Select(members.C(policyloadbalance.FieldLoadBalanceID)).From(members).
				Where(sql.EQ(members.C(policyloadbalance.FieldStoragePolicyID), policyID))
			if poolID > 0 {
				pools.Where(sql.EQ(members.C(policyloadbalance.FieldLoadBalanceID), poolID))
			}
			storageLifecycleRead(pools)
			grantedPool := sql.In(s.C(grouppolicy.FieldStoragePolicyID), pools)
			if poolID > 0 {
				s.Where(sql.And(sql.EQ(s.C(grouppolicy.FieldStoragePolicyID), poolID), grantedPool))
			} else {
				s.Where(sql.Or(sql.EQ(s.C(grouppolicy.FieldStoragePolicyID), policyID), grantedPool))
			}
		},
		storageLifecycleRead,
	).Exist(ctx)
}

// MySQL's repeatable-read snapshot may predate the lifecycle write. A locking
// read observes the current row; SQLite is already serialized by the write.
func storageLifecycleRead(s *sql.Selector) {
	if s.Dialect() != dialect.SQLite {
		s.ForUpdate()
	}
}

func SameStorageLocation(a, b *ent.StoragePolicy) bool {
	if a.Type != b.Type || a.Server != b.Server || a.BucketName != b.BucketName || a.NodeID != b.NodeID {
		return false
	}
	as, bs := a.Settings, b.Settings
	if as == nil {
		as = &types.PolicySetting{}
	}
	if bs == nil {
		bs = &types.PolicySetting{}
	}
	return as.ServerSideEndpoint == bs.ServerSideEndpoint && as.OdDriver == bs.OdDriver && as.Region == bs.Region && as.S3ForcePathStyle == bs.S3ForcePathStyle
}

func checkUploadPolicyDependencies(ctx context.Context, c *ent.Client, id int) error {
	pending, err := c.Entity.Query().Where(entity.StoragePolicyEntities(id), entity.UploadSessionIDNotNil(), storageLifecycleRead).All(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	for _, item := range pending {
		// Legacy placeholders without a recorded expiry require native cleanup.
		if item.Props == nil || item.Props.UploadExpiresAt == 0 || item.Props.UploadExpiresAt > now {
			return ErrStoragePolicyInUse
		}
	}
	return checkRelocationPolicyDependencies(ctx, c, id)
}

// Durable records remain authoritative after terminal status, history cleanup
// or account deletion. Unknown external writes are dependencies even if an
// earlier compensation pass observed no object at their exact owned key.
func checkRelocationPolicyDependencies(ctx context.Context, c *ent.Client, id int) error {
	used, err := c.RelocationItem.Query().Where(
		relocationitem.Or(relocationitem.SourcePolicyID(id), relocationitem.DestinationPolicyID(id)),
		relocationitem.Or(
			relocationitem.StateNotIn(relocationitem.StateCommitted, relocationitem.StateNoop, relocationitem.StateFailed),
			relocationitem.SourceCleanupEQ(relocationitem.SourceCleanupPending),
			relocationitem.HasAttemptsWith(
				relocationattempt.Or(
					relocationattempt.CleanupEQ(relocationattempt.CleanupPending),
					relocationattempt.IoStateIn(relocationattempt.IoStateInFlight, relocationattempt.IoStateUnknown),
				),
				storageLifecycleRead,
			),
		),
		storageLifecycleRead,
	).Exist(ctx)
	if err != nil {
		return err
	}
	if used {
		return ErrStoragePolicyInUse
	}
	return nil
}

func checkGroupPolicyDependencies(ctx context.Context, c *ent.Client, id int) error {
	// Native group deletion releases grants atomically; the one-time upgrade
	// removes old retired-group grants. Do not lock group rows here: group
	// writers acquire their group lock before this policy's lifecycle lock.
	granted, err := c.GroupPolicy.Query().Where(grouppolicy.StoragePolicyID(id), storageLifecycleRead).Exist(ctx)
	if err != nil {
		return err
	}
	if granted {
		return ErrStoragePolicyGranted
	}
	return nil
}
