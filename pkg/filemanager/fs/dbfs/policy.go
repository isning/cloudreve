package dbfs

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/storagepolicy"
)

func (f *DBFS) BindPolicy(ctx context.Context, uri *fs.URI, policyID int) error {
	if policyID <= 0 || uri.FileSystem() != constants.FileSystemMy {
		return fs.ErrNotSupportedAction
	}
	navigator, err := f.getNavigator(ctx, uri, NavigatorCapabilityBindPolicy, NavigatorCapabilityLockFile)
	if err != nil {
		return err
	}
	target, err := f.getFileByPath(ctx, navigator, uri)
	if err != nil {
		return err
	}
	if target.Type() != types.FileTypeFolder || target.IsRootFolder() || target.IsSymbolic() || target.InTrashBin() {
		return fs.ErrNotSupportedAction
	}
	if target.OwnerID() != f.user.ID {
		return fs.ErrOwnerOnly
	}
	ls, err := f.acquireByPath(ctx, -1, f.user, true, fs.LockApp(fs.ApplicationMount), &LockByPath{target.Uri(true), target, target.Type(), ""})
	if err != nil {
		return err
	}
	defer func() { _ = f.Release(ctx, ls) }()
	fc, tx, ctx, err := inventory.WithTx(ctx, f.fileClient)
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	err = inventory.LockActiveStorageOwner(ctx, fc.GetClient(), f.user.ID)
	if ent.IsNotFound(err) {
		return fs.ErrOwnerOnly
	}
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, inventory.CurrentPermissionReadCtx{}, true)
	current, err := fc.GetByID(ctx, target.ID())
	if err != nil {
		return err
	}
	if current.OwnerID != f.user.ID || current.Type != int(types.FileTypeFolder) || current.IsSymbolic || current.FileChildren == 0 {
		return fs.ErrNotSupportedAction
	}
	// Check the actual current root, including moves that happened after a cached
	// navigator was issued. Only a normal personal-drive tree can be bound.
	root := current
	seen := map[int]bool{}
	for root.FileChildren > 0 {
		if seen[root.ID] {
			return fmt.Errorf("directory ancestry has a cycle")
		}
		seen[root.ID] = true
		root, err = fc.GetByID(ctx, root.FileChildren)
		if err != nil {
			return err
		}
		if root.OwnerID != f.user.ID {
			return fs.ErrOwnerOnly
		}
	}
	if root.Name != inventory.RootFolderName {
		return fs.ErrNotSupportedAction
	}
	policy, err := inventory.LockStoragePolicy(ctx, fc.GetClient(), policyID)
	if err != nil {
		if ent.IsNotFound(err) {
			return serializer.NewError(serializer.CodeGroupNotAllowed, "Storage policy is unavailable", nil)
		}
		return err
	}
	if err = storagepolicy.New(f.userClient, f.storagePolicyClient).Revalidate(ctx, f.user.ID, policyID, 0); err != nil {
		if errors.Is(err, storagepolicy.ErrPolicyNotGranted) || errors.Is(err, storagepolicy.ErrNoAvailablePolicies) {
			return serializer.NewError(serializer.CodeGroupNotAllowed, "Storage policy is unavailable", err)
		}
		return serializer.NewError(serializer.CodeDBError, "Failed to load storage policy grants", err)
	}
	updated, err := fc.SetStoragePreference(ctx, current, policyID)
	if err != nil {
		return err
	}
	if current.StoragePolicyFiles != policyID {
		if err := f.recordAudit(ctx, types.AuditMount, target, types.LogEntry{StoragePolicyID: hashid.EncodePolicyID(f.hasher, policyID), StoragePolicy: policy.Name}, 0); err != nil {
			return err
		}
	}
	if err = inventory.Commit(tx); err != nil {
		return err
	}
	target.Model = updated
	f.emitFileModified(ctx, target)
	return nil
}
