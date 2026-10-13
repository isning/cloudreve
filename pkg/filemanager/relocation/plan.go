// Package relocation owns migration authorization, planning and physical entity
// movement, independently of future file/folder placement preferences.
package relocation

import (
	"context"
	"errors"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/storagepolicy"
)

type Plan struct {
	Owner       *ent.User
	Destination *ent.StoragePolicy
	FileIDs     []int
	Entity      *ent.Entity
	References  []types.RelocationReference
}

// PlanSingle validates the initial single-file transfer scope. All unsupported
// sources are rejected before queueing or any destination I/O.
func PlanSingle(ctx context.Context, dep dependency.Dep, ownerID int, src []string, destinationID int) (*Plan, error) {
	owner, err := dep.UserClient().GetActiveByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeNoPermissionErr, "Migration owner is unavailable", nil)
	}
	if owner.Edges.Group == nil || owner.Edges.Group.Permissions == nil || !owner.Edges.Group.Permissions.Enabled(int(types.GroupPermissionRelocate)) {
		return nil, serializer.NewError(serializer.CodeGroupNotAllowed, "Storage migration is disabled for this group", nil)
	}
	if len(src) != 1 || destinationID <= 0 {
		return nil, serializer.NewError(serializer.CodeParamErr, "Select one file and a valid destination", nil)
	}
	destination, err := storagepolicy.New(dep.UserClient(), dep.StoragePolicyClient()).Select(ctx, owner.ID, destinationID, 0)
	if err != nil {
		if errors.Is(err, storagepolicy.ErrPolicyNotGranted) || errors.Is(err, storagepolicy.ErrNoAvailablePolicies) {
			return nil, serializer.NewError(serializer.CodeGroupNotAllowed, "Storage destination is unavailable", nil)
		}
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to load storage destination", err)
	}
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(dep, owner)
	defer fm.Recycle()
	ownerEncoded := hashid.EncodeUserID(dep.HashIDEncoder(), owner.ID)
	uri, err := fs.NewUriFromString(src[0])
	if err != nil || uri.FileSystem() != constants.FileSystemMy || uri.ID(ownerEncoded) != ownerEncoded {
		return nil, serializer.NewError(serializer.CodeParamErr, "Migration requires an owned personal file", nil)
	}
	file, err := fm.Get(ctx, uri, dbfs.WithFileEntities(), dbfs.WithNotRoot(), dbfs.WithRequiredCapabilities(dbfs.NavigatorCapabilityRelocate, dbfs.NavigatorCapabilityDownloadFile))
	if err != nil {
		return nil, err
	}
	// Navigation models can retain upload-time timestamps. Plan from actual Ent
	// rows so the durable content snapshot never trusts that display cache.
	current, err := dep.DBClient().File.Query().Where(entfile.ID(file.ID())).WithEntities().Only(ctx)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to load migration source", nil)
	}
	if current.OwnerID != owner.ID || current.Type != int(types.FileTypeFile) || current.IsSymbolic || file.InTrashBin() || len(current.Edges.Entities) != 1 {
		return nil, fs.ErrNotSupportedAction
	}
	entity := fs.NewEntity(current.Edges.Entities[0])
	if entity.Type() != types.EntityTypeVersion || entity.UploadSessionID() != nil || entity.Encrypted() || entity.ReferenceCount() != 1 {
		return nil, serializer.NewError(serializer.CodeNoPermissionErr, "This migration source or transfer is not supported yet", nil)
	}
	return &Plan{Owner: owner, Destination: destination, FileIDs: []int{current.ID}, Entity: entity.Model(), References: []types.RelocationReference{{FileID: current.ID, PrimaryEntityID: current.PrimaryEntity, UpdatedAt: current.UpdatedAt}}}, nil
}
