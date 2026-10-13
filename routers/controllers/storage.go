package controllers

import (
	"net/http"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/cloudreve/Cloudreve/v4/service/user"
	"github.com/gin-gonic/gin"
)

func UserAvailableStoragePolicies(c *gin.Context) {
	policies, err := user.GetAvailableStoragePolicies(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusOK, serializer.Err(c, err))
		return
	}
	hasher := dependency.FromContext(c).HashIDEncoder()
	result := make([]*explorer.StoragePolicy, 0, len(policies))
	for _, policy := range policies {
		result = append(result, explorer.BuildStoragePolicy(policy, hasher))
	}
	c.JSON(http.StatusOK, serializer.Response{Data: result})
}

func BindStoragePolicy(c *gin.Context) {
	service := ParametersFromContext[*explorer.BindPolicyService](c, explorer.BindPolicyParamCtx{})
	if err := service.Bind(c); err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{})
}
