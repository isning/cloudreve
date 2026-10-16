package inventory

import (
	"context"
	"fmt"
	"slices"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/boolset"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
)

// LockPermissionOwners serializes permission-sensitive commits against file ACL
// and link changes using the existing owner rows, in a stable lock order.
func LockPermissionOwners(ctx context.Context, client *ent.Client, ids ...int) error {
	slices.Sort(ids)
	for i, id := range ids {
		if id <= 0 || i > 0 && ids[i-1] == id {
			continue
		}
		if err := client.User.Update().Where(user.ID(id)).AddStorage(0).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ResolvePermission uses the most specific matching rule, then everyone.
// A nil setting means an unrestricted personal file; legacy shares supply their
// read-only default before calling this function.
func ResolvePermission(setting *types.PermissionSetting, viewer, owner *ent.User, hasher hashid.Encoder) *boolset.BooleanSet {
	return DecidePermission(setting, viewer, owner, hasher).Grant
}

// PermissionDecision describes the existing rule match without changing the wire ACL.
type PermissionDecision struct {
	Grant *boolset.BooleanSet
	Rule  string
}

func DecidePermission(setting *types.PermissionSetting, viewer, owner *ent.User, hasher hashid.Encoder) PermissionDecision {
	if viewer.ID == owner.ID || viewer.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) || setting == nil {
		return PermissionDecision{types.AllFilePermissions(), "owner_or_unrestricted"}
	}
	var grant *boolset.BooleanSet
	rule := "anonymous"
	if IsAnonymousUser(viewer) {
		grant = setting.Anonymous
	} else {
		rule = "user_explicit"
		grant = setting.UserExplicit[hashid.EncodeUserID(hasher, viewer.ID)]
		if grant == nil {
			rule = "group_explicit"
			grant = setting.GroupExplicit[hashid.EncodeGroupID(hasher, viewer.GroupUsers)]
		}
		if grant == nil {
			if viewer.GroupUsers == owner.GroupUsers {
				rule = "same_group"
				grant = setting.SameGroup
			} else {
				rule = "other"
				grant = setting.Other
			}
		}
	}
	if grant == nil {
		rule = "everyone"
		grant = setting.Everyone
	}
	if grant == nil {
		return PermissionDecision{types.AllFilePermissions(), "default"}
	}
	return PermissionDecision{grant, rule}
}

func SharePermissionSetting(s *ent.Share) *types.PermissionSetting {
	if s.Props != nil && s.Props.Permissions != nil {
		return s.Props.Permissions
	}
	return &types.PermissionSetting{Everyone: types.ReadOnlyPermissions(), Anonymous: types.ReadOnlyPermissions()}
}

// ResolveSharePermission includes the link creator's existing management exception.
func ResolveSharePermission(s *ent.Share, viewer, owner *ent.User, hasher hashid.Encoder) *boolset.BooleanSet {
	if s.Edges.User != nil && viewer.ID == s.Edges.User.ID {
		return types.AllFilePermissions()
	}
	return ResolvePermission(SharePermissionSetting(s), viewer, owner, hasher)
}

// CheckShareAccess checks current link/account and group gates. Passwords are
// checked separately by the entrypoint, so discovery can project locked links.
func CheckShareAccess(s *ent.Share, viewer *ent.User) error {
	if err := IsValidShare(s); err != nil {
		return err
	}
	if viewer.ID == s.Edges.File.OwnerID || viewer.ID == s.Edges.User.ID ||
		viewer.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) ||
		viewer.Edges.Group.Permissions.Enabled(int(types.GroupPermissionShareDownload)) {
		return nil
	}
	code := serializer.CodeNoPermissionErr
	if IsAnonymousUser(viewer) {
		code = serializer.CodeAnonymouseAccessDenied
	}
	return serializer.NewError(code, "You don't have permission to access share links", nil)
}

// CanManageShare includes the underlying file owner so delegated links remain
// revocable by the person responsible for the stored files. Load both edges.
func CanManageShare(s *ent.Share, requester *ent.User) bool {
	if IsAnonymousUser(requester) {
		return false
	}
	return requester.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) ||
		s.Edges.User != nil && s.Edges.User.ID == requester.ID ||
		s.Edges.File != nil && s.Edges.File.OwnerID == requester.ID
}

// ValidatePermissionSetting checks the public wire contract before persistence.
// The anonymous escalation restriction applies when assigning a grant, so a
// later group change cannot retroactively rewrite an existing ACL.
func ValidatePermissionSetting(setting *types.PermissionSetting, setter *ent.User, hasher hashid.Encoder, previous *types.PermissionSetting) error {
	if setting == nil {
		return nil
	}
	invalid := func() error { return serializer.NewError(serializer.CodeParamErr, "Invalid permission setting", nil) }
	validGrant := func(grant *boolset.BooleanSet) bool {
		return grant == nil || len(*grant) <= 1 && (len(*grant) == 0 || (*grant)[0]&0xc0 == 0)
	}
	for _, grant := range []*boolset.BooleanSet{setting.Everyone, setting.Anonymous, setting.SameGroup, setting.Other} {
		if !validGrant(grant) {
			return invalid()
		}
	}
	if len(setting.UserExplicit)+len(setting.GroupExplicit) > 256 {
		return invalid()
	}
	for kind, grants := range map[int]map[string]*boolset.BooleanSet{hashid.UserID: setting.UserExplicit, hashid.GroupID: setting.GroupExplicit} {
		for key, grant := range grants {
			if len(key) > 64 {
				return invalid()
			}
			id, err := hasher.Decode(key, kind)
			if err != nil || id <= 0 || grant == nil || !validGrant(grant) {
				return invalid()
			}
		}
	}
	if !setter.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) && !setter.Edges.Group.Permissions.Enabled(int(types.GroupPermissionSetAnonymousPermission)) {
		anonymous := anonymousPermission(setting)
		old := types.ReadOnlyPermissions()
		if previous != nil {
			old = anonymousPermission(previous)
		}
		for _, bit := range []types.FilePermission{types.FilePermissionCreate, types.FilePermissionUpdate, types.FilePermissionDelete, types.FilePermissionShare} {
			if anonymous.Enabled(int(bit)) && !old.Enabled(int(bit)) {
				return serializer.NewError(serializer.CodeGroupNotAllowed, "Your group cannot grant anonymous write permissions", nil)
			}
		}
	}
	return nil
}

func anonymousPermission(setting *types.PermissionSetting) *boolset.BooleanSet {
	if setting.Anonymous != nil {
		return setting.Anonymous
	}
	if setting.Everyone != nil {
		return setting.Everyone
	}
	return types.AllFilePermissions()
}

func PermissionDenied(permission types.FilePermission) error {
	return serializer.NewError(serializer.CodeNoPermissionErr, "Permission denied", fmt.Errorf("missing file permission %d", permission))
}
