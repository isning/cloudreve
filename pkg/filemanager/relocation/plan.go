// Package relocation owns migration authorization, planning and physical entity
// movement, independently of future file/folder placement preferences.
package relocation

import (
	"context"
	"errors"
	"net/url"
	"sort"

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
	Entity      *ent.Entity
	References  []types.RelocationReference
}

type Selection struct {
	Owner       *ent.User
	Destination *ent.StoragePolicy
	Roots       map[int]*fs.URI
	FileIDs     []int
	Items       []*Plan
}

// ValidateSources checks only selected roots at the HTTP boundary. Recursive
// enumeration and whole-plan validation belong to the persistent worker.
func ValidateSources(ctx context.Context, dep dependency.Dep, ownerID int, src []string, destinationID int) (*Selection, error) {
	owner, err := dep.UserClient().GetActiveByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeNoPermissionErr, "Migration owner is unavailable", nil)
	}
	if owner.Edges.Group == nil || owner.Edges.Group.Permissions == nil || !owner.Edges.Group.Permissions.Enabled(int(types.GroupPermissionRelocate)) {
		return nil, serializer.NewError(serializer.CodeGroupNotAllowed, "Storage migration is disabled for this group", nil)
	}
	if len(src) == 0 || destinationID <= 0 {
		return nil, serializer.NewError(serializer.CodeParamErr, "Select sources and a valid destination", nil)
	}
	destination, err := storagepolicy.New(dep.UserClient(), dep.StoragePolicyClient()).Select(ctx, owner.ID, destinationID, 0)
	if err != nil {
		if errors.Is(err, storagepolicy.ErrPolicyNotGranted) || errors.Is(err, storagepolicy.ErrNoAvailablePolicies) {
			return nil, serializer.NewError(serializer.CodeGroupNotAllowed, "Storage destination is unavailable", nil)
		}
		return nil, serializer.NewError(serializer.CodeDBError, "Failed to load storage destination", err)
	}
	if _, err := storagepolicy.Choose(destination); err != nil {
		return nil, serializer.NewError(serializer.CodeParamErr, err.Error(), nil)
	}
	ctx = context.WithValue(ctx, inventory.UserCtx{}, owner)
	fm := manager.NewFileManager(dep, owner)
	defer fm.Recycle()
	ownerEncoded := hashid.EncodeUserID(dep.HashIDEncoder(), owner.ID)
	selection := &Selection{Owner: owner, Destination: destination, Roots: make(map[int]*fs.URI)}
	for _, source := range src {
		uri, err := fs.NewUriFromString(source)
		if err != nil || uri.FileSystem() != constants.FileSystemMy || uri.ID(ownerEncoded) != ownerEncoded {
			return nil, serializer.NewError(serializer.CodeParamErr, "Migration requires owned personal sources", nil)
		}
		file, err := fm.Get(ctx, uri, dbfs.WithFileEntities(), dbfs.WithRequiredCapabilities(dbfs.NavigatorCapabilityRelocate, dbfs.NavigatorCapabilityDownloadFile))
		if err != nil {
			return nil, err
		}
		current, err := dep.DBClient().File.Query().Where(entfile.ID(file.ID())).WithEntities().Only(ctx)
		if err != nil {
			return nil, serializer.NewError(serializer.CodeDBError, "Failed to load migration source", nil)
		}
		if current.OwnerID != owner.ID || current.IsSymbolic || file.InTrashBin() || (current.Type != int(types.FileTypeFile) && current.Type != int(types.FileTypeFolder)) {
			return nil, fs.ErrNotSupportedAction
		}
		if current.Type == int(types.FileTypeFile) {
			if err := validateEntities(current); err != nil {
				return nil, err
			}
		}
		uri.U.User = url.User(ownerEncoded)
		selection.Roots[current.ID] = uri
	}
	return selection, nil
}

func validateEntities(file *ent.File) error {
	if len(file.Edges.Entities) == 0 {
		return fs.ErrNotSupportedAction
	}
	for _, model := range file.Edges.Entities {
		e := fs.NewEntity(model)
		if (e.Type() != types.EntityTypeVersion && e.Type() != types.EntityTypeThumbnail && e.Type() != types.EntityTypeLivePhoto) || e.UploadSessionID() != nil || e.ReferenceCount() < 1 || e.Size() < 0 {
			return serializer.NewError(serializer.CodeNoPermissionErr, "Migration contains an unsupported or incomplete entity", nil)
		}
	}
	return nil
}

// PlanSelection deduplicates files and shared associations before publishing any
// journal rows. The resulting immutable snapshot excludes later additions.
func PlanSelection(ctx context.Context, dep dependency.Dep, ownerID int, src []string, destinationID int) (*Selection, error) {
	selection, err := ValidateSources(ctx, dep, ownerID, src, destinationID)
	if err != nil {
		return nil, err
	}
	type pending struct {
		id  int
		uri *fs.URI
	}
	queue := make([]pending, 0, len(selection.Roots))
	for id, uri := range selection.Roots {
		queue = append(queue, pending{id, uri})
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].id < queue[j].id })
	seen := make(map[int]bool)
	items := make(map[int]*Plan)
	for len(queue) > 0 {
		next := queue[0]
		queue = queue[1:]
		if seen[next.id] {
			continue
		}
		seen[next.id] = true
		file, err := dep.DBClient().File.Query().Where(entfile.ID(next.id)).WithEntities().Only(ctx)
		if err != nil || file.OwnerID != ownerID || file.IsSymbolic {
			return nil, ErrConflict
		}
		selection.FileIDs = append(selection.FileIDs, file.ID)
		switch types.FileType(file.Type) {
		case types.FileTypeFolder:
			children, err := dep.DBClient().File.Query().Where(entfile.FileChildren(file.ID)).Order(entfile.ByID()).All(ctx)
			if err != nil {
				return nil, errors.New("failed to enumerate migration folder")
			}
			for _, child := range children {
				queue = append(queue, pending{child.ID, next.uri.Join(child.Name)})
			}
		case types.FileTypeFile:
			if err := validateEntities(file); err != nil {
				return nil, err
			}
			for _, e := range file.Edges.Entities {
				item := items[e.ID]
				if item == nil {
					concrete, err := storagepolicy.Choose(selection.Destination)
					if err != nil {
						return nil, err
					}
					item = &Plan{Owner: selection.Owner, Destination: concrete, Entity: e}
					items[e.ID] = item
				}
				item.References = append(item.References, types.RelocationReference{FileID: file.ID, URI: next.uri.String(), PrimaryEntityID: file.PrimaryEntity, UpdatedAt: file.UpdatedAt})
			}
		default:
			return nil, fs.ErrNotSupportedAction
		}
	}
	sort.Ints(selection.FileIDs)
	for _, item := range items {
		sort.Slice(item.References, func(i, j int) bool { return item.References[i].FileID < item.References[j].FileID })
		selection.Items = append(selection.Items, item)
	}
	sort.Slice(selection.Items, func(i, j int) bool { return selection.Items[i].Entity.ID < selection.Items[j].Entity.ID })
	return selection, nil
}
