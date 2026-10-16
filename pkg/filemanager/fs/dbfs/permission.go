package dbfs

import (
	"context"
	"fmt"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"net/url"
	"reflect"
	"sort"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/ent"
	entuser "github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
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

func (f *DBFS) SetPermissions(ctx context.Context, uris []*fs.URI, setting *types.PermissionSetting, expectedIDs ...int) error {
	if len(expectedIDs) > 0 && len(expectedIDs) != len(uris) {
		return serializer.NewError(serializer.CodeParamErr, "Expected file IDs must match the URI count", nil)
	}
	targets := make([]*File, 0, len(uris))
	locks := make([]*LockByPath, 0, len(uris))
	seen := make(map[int]bool)
	expected := make(map[int]int, len(expectedIDs))
	for i, uri := range uris {
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
		if len(expectedIDs) > 0 {
			if previous, ok := expected[target.ID()]; ok && previous != expectedIDs[i] {
				return fs.ErrModified
			}
			expected[target.ID()] = expectedIDs[i]
		}
		if seen[target.ID()] {
			continue
		}
		seen[target.ID()] = true
		targets = append(targets, target)
		locks = append(locks, &LockByPath{target.Uri(true), target, target.Type(), ""})
	}
	ls, err := f.acquireByPath(ctx, -1, f.user, true, fs.LockApp(fs.ApplicationUpdateMetadata), locks...)
	defer func() { _ = f.Release(ctx, ls) }()
	if err != nil {
		return err
	}
	fc, tx, ctx, err := inventory.WithTx(ctx, f.fileClient)
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	setter, err := f.lockPermissionOwners(ctx, fc, targets...)
	if err != nil {
		return err
	}
	currentFiles := make([]*ent.File, 0, len(targets))
	for _, target := range targets {
		// Read after acquiring the canonical file lock, preserving concurrent
		// view changes and other properties when updating only this ACL.
		current, err := fc.GetClient().File.Get(ctx, target.ID())
		if err != nil {
			return err
		}
		if current.OwnerID != setter.ID && !setter.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
			return fs.ErrOwnerOnly
		}
		if id, ok := expected[target.ID()]; ok && current.ID != id {
			return fs.ErrModified
		}
		currentFiles = append(currentFiles, current)
	}
	// Check every identity under the canonical locks and owner fence before any
	// mutation or audit row, including no-op saves and clearing inherited rules.
	for i, current := range currentFiles {
		props := types.FileProps{}
		if current.Props != nil {
			props = *current.Props
		}
		if reflect.DeepEqual(props.Permissions, setting) {
			continue
		}
		if err := inventory.ValidatePermissionSetting(setting, setter, f.hasher, props.Permissions); err != nil {
			return err
		}
		props.Permissions = setting
		if _, err := fc.UpdateProps(ctx, current, &props); err != nil {
			return err
		}
		if err := f.recordAudit(ctx, types.AuditSetFilePermission, targets[i], types.LogEntry{}, 0); err != nil {
			return err
		}
	}
	return inventory.Commit(tx)
}

// Reuse the owner-row ordering used by storage reservations and ownership
// transfers. Authorization reads follow this fence inside the same transaction.
func (f *DBFS) lockPermissionOwners(ctx context.Context, fc inventory.FileClient, targets ...*File) (*ent.User, error) {
	ids := map[int]bool{}
	for _, target := range targets {
		ids[target.OwnerID()] = true
	}
	if f.user.ID > 0 {
		ids[f.user.ID] = true
	}
	ordered := make([]int, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Ints(ordered)
	if err := inventory.LockPermissionOwners(ctx, fc.GetClient(), ordered...); err != nil {
		return nil, err
	}
	uc := f.userClient.SetClient(fc.GetClient()).(inventory.UserClient)
	actor, err := uc.GetLoginUserByID(ctx, f.user.ID)
	if err != nil {
		return nil, err
	}
	// Native personal navigation lets a current administrator manage inactive
	// accounts. Share entries still require active owners, including when a link
	// becomes invalid after the initial navigation but before this fence.
	requireActive := map[int]bool{actor.ID: true}
	isAdmin := actor.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin))
	for _, target := range targets {
		if !isAdmin || target.Uri(false).FileSystem() != constants.FileSystemMy {
			requireActive[target.OwnerID()] = true
		}
	}
	for _, id := range ordered {
		// MySQL reports changed rows for a no-op update. Check existence
		// separately after the row lock rather than treating zero as missing.
		query := fc.GetClient().User.Query().Where(entuser.ID(id))
		if requireActive[id] {
			query.Where(entuser.StatusEQ(entuser.StatusActive))
		}
		exists, err := query.Exist(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrPermissionDenied
		}
	}
	return actor, nil
}

// PermissionContext explains navigation's nearest rule while preserving the
// effective mask already computed by that navigation. Only managers expose it.
func (f *File) PermissionContext(viewer *ent.User, hasher hashid.Encoder) *types.PermissionContext {
	result := &types.PermissionContext{Extension: "ccsn", Source: "entry", Effective: f.PermissionBs}
	shared := f.Uri(false).FileSystem() == constants.FileSystemShare
	result.ContextDependent = !shared
	var setting *types.PermissionSetting
	for node := f; node != nil; node = node.Parent {
		if shared && node.LinkPermissionSetting != nil {
			result.Source = "link"
			result.SourceURI = node.Uri(false).Root().String()
			setting = node.LinkPermissionSetting
			break
		}
		if node.Model.Props != nil && node.Model.Props.Permissions != nil {
			result.Source = "ancestor"
			if node == f {
				result.Source = "explicit"
			}
			result.SourceURI = node.Uri(false).String()
			setting = node.Model.Props.Permissions
			break
		}
		if shared && node.IsUserRoot {
			break
		}
	}
	if result.SourceURI != "" {
		uri, _ := fs.NewUriFromString(result.SourceURI)
		if uri.U.User != nil {
			uri.U.User = url.User(uri.U.User.Username())
		}
		result.SourceURI = uri.String()
	}
	decision := inventory.DecidePermission(setting, viewer, f.Owner(), hasher)
	result.MatchedRule = decision.Rule
	if result.Effective == nil {
		result.Effective = decision.Grant
	}
	return result
}

// A permissionCheck reopens the original entry under the transaction's owner
// fence. Planning objects and context hints are never final authorization.
type permissionCheck struct {
	file       *File
	permission types.FilePermission
	recursive  bool
}

func (f *DBFS) ValidateSharePermission(ctx context.Context, target fs.File) (*ent.User, error) {
	fc, tx := inventory.InheritTx(ctx, f.fileClient)
	if tx == nil {
		return nil, fmt.Errorf("share authorization requires a transaction")
	}
	file, ok := target.(*File)
	if !ok {
		return nil, ErrPermissionDenied
	}
	if err := f.revalidatePermissions(ctx, fc, permissionCheck{file, types.FilePermissionShare, false}); err != nil {
		return nil, err
	}
	return f.userClient.SetClient(fc.GetClient()).(inventory.UserClient).GetLoginUserByID(ctx, f.user.ID)
}

func (f *DBFS) revalidatePermissions(ctx context.Context, fc inventory.FileClient, checks ...permissionCheck) error {
	if bypass, _ := ctx.Value(ByPassOwnerCheckCtxKey{}).(bool); bypass {
		return nil
	}
	targets := make([]*File, 0, len(checks))
	for _, check := range checks {
		targets = append(targets, check.file)
	}
	actor, err := f.lockPermissionOwners(ctx, fc, targets...)
	if err != nil {
		return err
	}
	uc := f.userClient.SetClient(fc.GetClient()).(inventory.UserClient)
	sc := f.shareClient.SetClient(fc.GetClient()).(inventory.ShareClient)
	allowed := func(file *File, permission types.FilePermission) bool {
		return file.OwnerID() == actor.ID || actor.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) ||
			file.Uri(false).FileSystem() == constants.FileSystemShare && file.HasPermission(permission)
	}
	for _, check := range checks {
		uri := check.file.Uri(false)
		var navigator Navigator
		config := f.settingClient.DBFS(ctx)
		switch uri.FileSystem() {
		case constants.FileSystemShare:
			navigator = NewShareNavigator(actor, fc, sc, f.l, config, f.hasher)
		case constants.FileSystemMy:
			navigator = NewMyNavigator(actor, fc, uc, f.l, config, f.hasher)
		case constants.FileSystemTrash:
			navigator = NewTrashNavigator(actor, fc, f.l, config, f.hasher)
		default:
			return ErrPermissionDenied
		}
		err := func() error {
			defer navigator.Recycle()
			target, err := navigator.To(ctx, uri)
			if err != nil {
				return ErrPermissionDenied
			}
			if target.ID() != check.file.ID() || target.OwnerID() != check.file.OwnerID() {
				return fs.ErrModified
			}
			if !allowed(target, check.permission) {
				return inventory.PermissionDenied(check.permission)
			}
			if check.recursive && target.OwnerID() != actor.ID && !actor.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
				limit := max(actor.Edges.Group.Settings.MaxWalkedFiles, 1)
				return navigator.Walk(ctx, []*File{target}, limit, intsets.MaxInt, func(files []*File, _ int) error {
					for _, file := range files {
						if !allowed(file, check.permission) {
							return inventory.PermissionDenied(check.permission)
						}
					}
					return nil
				})
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
