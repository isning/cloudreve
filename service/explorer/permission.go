package explorer

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type FilePermissionParamCtx struct{}
type FilePermissionService struct {
	Uris    []string                 `json:"uris" binding:"required,min=1,max=1000"`
	Setting *types.PermissionSetting `json:"setting"`
}

func (s *FilePermissionService) GetUris() []string { return s.Uris }

func (s *FilePermissionService) Set(c *gin.Context, clear bool) error {
	if !clear && s.Setting == nil {
		return serializer.NewError(serializer.CodeParamErr, "Permission setting is required", nil)
	}
	setting := s.Setting
	if clear {
		setting = nil
	}
	uris, err := fs.NewUriFromStrings(s.Uris...)
	if err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Invalid file URI", nil)
	}
	m := manager.NewFileManager(dependency.FromContext(c), inventory.UserFromContext(c))
	defer m.Recycle()
	return m.SetPermissions(c, uris, setting)
}
