package controllers

import (
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/service/admin"
	"github.com/cloudreve/Cloudreve/v4/service/explorer"
	"github.com/gin-gonic/gin"
)

func FileActivities(c *gin.Context) {
	service := ParametersFromContext[*explorer.FileActivitiesService](c, explorer.FileActivitiesParamCtx{})
	result, err := service.List(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{Data: result})
}

func AdminListAuditLogs(c *gin.Context) {
	service := ParametersFromContext[*admin.AdminListService](c, admin.AdminListServiceParamsCtx{})
	result, err := service.ListAuditLogs(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{Data: result})
}

func AdminGetAuditLog(c *gin.Context) {
	service := ParametersFromContext[*admin.SingleAuditLogService](c, admin.SingleAuditLogParamCtx{})
	result, err := service.Get(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{Data: result})
}

func AdminDeleteAuditLogs(c *gin.Context) {
	err := ParametersFromContext[*admin.BatchAuditLogService](c, admin.BatchAuditLogParamCtx{}).Delete(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{})
}
func AdminCleanupAuditLogs(c *gin.Context) {
	err := ParametersFromContext[*admin.CleanupAuditLogService](c, admin.CleanupAuditLogParamCtx{}).Cleanup(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{})
}
func AdminCreateAuditArchive(c *gin.Context) {
	result, err := ParametersFromContext[*admin.CreateAuditArchiveService](c, admin.CreateAuditArchiveParamCtx{}).Create(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{Data: result})
}
func AdminAuditArchiveStatus(c *gin.Context) {
	result, err := ParametersFromContext[*admin.AuditArchiveService](c, admin.AuditArchiveParamCtx{}).Status(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{Data: result})
}
func AdminPurgeAuditArchive(c *gin.Context) {
	err := ParametersFromContext[*admin.AuditArchiveService](c, admin.AuditArchiveParamCtx{}).Purge(c)
	if err != nil {
		c.JSON(200, serializer.Err(c, err))
		return
	}
	c.JSON(200, serializer.Response{})
}
func DownloadAuditArchive(c *gin.Context) {
	err := ParametersFromContext[*admin.AuditArchiveService](c, admin.AuditArchiveParamCtx{}).Download(c)
	if err != nil && !c.Writer.Written() {
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.JSON(200, serializer.Err(c, err))
	}
}
