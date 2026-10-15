package controllers

import (
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
)

func SetFilePermissions(c *gin.Context) {
	s := ParametersFromContext[*explorer.FilePermissionService](c, explorer.FilePermissionParamCtx{})
	if err := s.Set(c, c.Request.Method == "DELETE"); err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{})
}

func ListPermissionGroups(c *gin.Context) {
	groups, err := user.ListAllGroups(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	hasher := dependency.FromContext(c).HashIDEncoder()
	type group struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	result := make([]group, 0, len(groups))
	for _, item := range groups {
		result = append(result, group{ID: hashid.EncodeGroupID(hasher, item.ID), Name: item.Name})
	}
	c.JSON(200, serializer.Response{Data: result})
}
