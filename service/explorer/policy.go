package explorer

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type BindPolicyParamCtx struct{}
type BindPolicyService struct {
	Uri      string `json:"uri" binding:"required"`
	PolicyID string `json:"policy_id" binding:"required"`
}

func (s *BindPolicyService) Bind(c *gin.Context) error {
	dep := dependency.FromContext(c)
	id, err := dep.HashIDEncoder().Decode(s.PolicyID, hashid.PolicyID)
	if err != nil || id <= 0 {
		return serializer.NewError(serializer.CodeParamErr, "Invalid storage policy", nil)
	}
	uri, err := fs.NewUriFromString(s.Uri)
	if err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Invalid directory URI", nil)
	}
	m := manager.NewFileManager(dep, inventory.UserFromContext(c))
	defer m.Recycle()
	return m.BindPolicy(c, uri, id)
}
