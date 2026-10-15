package dbfs

import (
	"context"
	"reflect"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"golang.org/x/tools/container/intsets"
)

func (f *File) HasPermission(permission types.FilePermission) bool {
	return f.PermissionBs == nil || f.PermissionBs.Enabled(int(permission))
}

func (f *File) CanList() bool {
	return f.HasPermission(types.FilePermissionList) || f.HasPermission(types.FilePermissionRead)
}

func (f *DBFS) canAccess(ctx context.Context, target *File, permission types.FilePermission) bool {
	if bypass, _ := ctx.Value(ByPassOwnerCheckCtxKey{}).(bool); bypass || target.OwnerID() == f.user.ID || f.user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
		return true
	}
	return target.Uri(false).FileSystem() == constants.FileSystemShare && target.HasPermission(permission)
}

func shareFileCapabilities(permission *boolset.BooleanSet) *boolset.BooleanSet {
	read := permission.Enabled(int(types.FilePermissionRead))
	list := read || permission.Enabled(int(types.FilePermissionList))
	create := permission.Enabled(int(types.FilePermissionCreate))
	update := permission.Enabled(int(types.FilePermissionUpdate))
	remove := permission.Enabled(int(types.FilePermissionDelete))
	capabilities := &boolset.BooleanSet{}
	boolset.Sets(map[NavigatorCapability]bool{
		NavigatorCapabilityCreateFile: create, NavigatorCapabilityUploadFile: create || update,
		NavigatorCapabilityRenameFile: update, NavigatorCapabilityUpdateMetadata: update,
		NavigatorCapabilityDownloadFile: read, NavigatorCapabilityGenerateThumb: list,
		NavigatorCapabilityListChildren: list || create, NavigatorCapabilityEnterFolder: list || create,
		NavigatorCapabilityInfo: list, NavigatorCapabilityVersionControl: read,
		NavigatorCapabilityDeleteFile: remove, NavigatorCapabilitySoftDelete: remove,
		NavigatorCapabilityShare:    permission.Enabled(int(types.FilePermissionShare)),
		NavigatorCapabilityLockFile: true, NavigatorCapabilityModifyProps: update,
	}, capabilities)
	return capabilities
}

// applyPermission stops inheritance at the share root. Its own file ACL is
// deliberately replaced by the link ACL; descendants use their nearest ACL.
func (b *baseNavigator) applyPermission(file *File) *File {
	root := file.UserRoot()
	if root == nil || root.Uri(false).FileSystem() != constants.FileSystemShare {
		return file
	}
	if file != root && file.Model.Props != nil && file.Model.Props.Permissions != nil {
		file.PermissionBs = inventory.ResolvePermission(file.Model.Props.Permissions, b.user, file.Owner(), b.hasher)
	}
	if file.PermissionBs == nil {
		file.PermissionBs = root.PermissionBs
	}
	file.CapabilitiesBs = shareFileCapabilities(file.PermissionBs)
	return file
}

func requireCapabilities(file *File, capabilities ...NavigatorCapability) error {
	for _, capability := range capabilities {
		if file.CapabilitiesBs == nil || !file.CapabilitiesBs.Enabled(int(capability)) {
			return ErrPermissionDenied
		}
	}
	return nil
}

// Destructive subtree operations must examine hidden descendants as well.
// Navigator.Walk applies inherited ACLs without filtering away denied nodes.
func (f *DBFS) requireSubtreePermission(ctx context.Context, n Navigator, files []*File, permission types.FilePermission) error {
	if len(files) == 0 || files[0].OwnerID() == f.user.ID || f.user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
		return nil
	}
	reset, err := n.FollowTx(ctx)
	if err != nil {
		return err
	}
	defer reset()
	return n.Walk(ctx, files, intsets.MaxInt, intsets.MaxInt, func(files []*File, _ int) error {
		for _, file := range files {
			if !f.canAccess(ctx, file, permission) {
				return inventory.PermissionDenied(permission)
			}
		}
		return nil
	})
}

func (f *DBFS) SetPermissions(ctx context.Context, uris []*fs.URI, setting *types.PermissionSetting) error {
	targets := make([]*File, 0, len(uris))
	locks := make([]*LockByPath, 0, len(uris))
	for _, uri := range uris {
		navigator, err := f.getNavigator(ctx, uri)
		if err != nil {
			return err
		}
		target, err := f.getFileByPath(ctx, navigator, uri)
		if err != nil {
			return err
		}
		if target.OwnerID() != f.user.ID && !f.user.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
			return fs.ErrOwnerOnly
		}
		targets = append(targets, target)
		locks = append(locks, &LockByPath{target.Uri(true), target, target.Type(), ""})
	}
	ls, err := f.acquireByPath(ctx, -1, f.user, true, fs.LockApp(fs.ApplicationUpdateMetadata), locks...)
	if err != nil {
		return err
	}
	defer func() { _ = f.Release(ctx, ls) }()
	fc, tx, ctx, err := inventory.WithTx(ctx, f.fileClient)
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	for _, target := range targets {
		// Read after acquiring the canonical file lock, preserving concurrent
		// view changes and other properties when updating only this ACL.
		current, err := fc.GetClient().File.Get(ctx, target.ID())
		if err != nil {
			return err
		}
		props := types.FileProps{}
		if current.Props != nil {
			props = *current.Props
		}
		if reflect.DeepEqual(props.Permissions, setting) {
			continue
		}
		if err := inventory.ValidatePermissionSetting(setting, f.user, f.hasher, props.Permissions); err != nil {
			return err
		}
		props.Permissions = setting
		if _, err := fc.UpdateProps(ctx, current, &props); err != nil {
			return err
		}
		if err := f.recordAudit(ctx, types.AuditSetFilePermission, target, types.LogEntry{}, 0); err != nil {
			return err
		}
	}
	return inventory.Commit(tx)
}
