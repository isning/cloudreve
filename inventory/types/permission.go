package types

import "github.com/cloudreve/Cloudreve/v4/pkg/boolset"

const (
	FilePermissionRead FilePermission = iota
	FilePermissionUpdate
	FilePermissionCreate
	FilePermissionDelete
	FilePermissionShare
	FilePermissionList
)

// PermissionSetting preserves absent rules separately from explicit zero grants.
type PermissionSetting struct {
	UserExplicit  map[string]*boolset.BooleanSet `json:"user_explicit,omitempty"`
	GroupExplicit map[string]*boolset.BooleanSet `json:"group_explicit,omitempty"`
	SameGroup     *boolset.BooleanSet            `json:"same_group,omitempty"`
	Other         *boolset.BooleanSet            `json:"other,omitempty"`
	Anonymous     *boolset.BooleanSet            `json:"anonymous,omitempty"`
	Everyone      *boolset.BooleanSet            `json:"everyone,omitempty"`
}

func ReadOnlyPermissions() *boolset.BooleanSet { return &boolset.BooleanSet{0x21} }
func AllFilePermissions() *boolset.BooleanSet  { return &boolset.BooleanSet{0x3f} }
