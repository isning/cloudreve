package explorer

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type FilePermissionParamCtx struct{}
type FilePermissionService struct {
	Uris    []string                 `json:"uris" binding:"required,min=1,max=1000"`
	Setting *types.PermissionSetting `json:"setting"`
	// ExpectedIDs is an optional CCSN precondition, aligned with Uris. Legacy
	// clients that omit it retain the native URI-based operation.
	ExpectedIDs []string `json:"expected_ids,omitempty"`
}

func (s *FilePermissionService) GetUris() []string { return s.Uris }

func (s *FilePermissionService) Set(c *gin.Context, clear bool) error {
	if !clear && s.Setting == nil {
		return serializer.NewError(serializer.CodeParamErr, "Permission setting is required", nil)
	}
	dep := dependency.FromContext(c)
	var expectedIDs []int
	if s.ExpectedIDs != nil {
		if len(s.ExpectedIDs) != len(s.Uris) {
			return serializer.NewError(serializer.CodeParamErr, "Expected file IDs must match the URI count", nil)
		}
		expectedIDs = make([]int, len(s.ExpectedIDs))
		for i, encoded := range s.ExpectedIDs {
			if len(encoded) == 0 || len(encoded) > 64 {
				return serializer.NewError(serializer.CodeParamErr, "Invalid expected file ID", nil)
			}
			id, err := dep.HashIDEncoder().Decode(encoded, hashid.FileID)
			if err != nil || id <= 0 {
				return serializer.NewError(serializer.CodeParamErr, "Invalid expected file ID", nil)
			}
			expectedIDs[i] = id
		}
	}
	setting := s.Setting
	if clear {
		setting = nil
	}
	uris, err := fs.NewUriFromStrings(s.Uris...)
	if err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Invalid file URI", nil)
	}
	m := manager.NewFileManager(dep, inventory.UserFromContext(c))
	defer m.Recycle()
	return m.SetPermissions(c, uris, setting, expectedIDs...)
}
