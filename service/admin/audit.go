package admin

import (
	"math"
	"strconv"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/audit"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type AuditListResponse struct {
	Logs       []audit.AdminLog             `json:"logs"`
	Pagination *inventory.PaginationResults `json:"pagination"`
}

func (s *AdminListService) ListAuditLogs(c *gin.Context) (*AuditListResponse, error) {
	if s.Page < 1 || s.PageSize < 1 || s.PageSize > 500 || s.Page > math.MaxInt/s.PageSize {
		return nil, serializer.NewError(serializer.CodeParamErr, "Invalid audit pagination", nil)
	}
	dep := dependency.FromContext(c)
	q := dep.DBClient().AuditLog.Query()
	for field, value := range s.Conditions {
		if value == "" {
			continue
		}
		switch field {
		case "audit_log_user", "audit_log_file":
			kind := hashid.UserID
			if field == "audit_log_file" {
				kind = hashid.FileID
			}
			id, err := strconv.Atoi(value)
			if err != nil {
				id, err = dep.HashIDEncoder().Decode(value, kind)
			}
			if err != nil || id < 0 {
				return nil, serializer.NewError(serializer.CodeParamErr, "Invalid audit object ID", nil)
			}
			if kind == hashid.UserID {
				q.Where(auditlog.UserID(id))
			} else {
				q.Where(auditlog.FileID(id))
			}
		case "audit_log_ip":
			q.Where(auditlog.IP(value))
		case "audit_log_correlation_id":
			q.Where(auditlog.CorrelationID(value))
		case "audit_log_category":
			if len(value) > 512 {
				return nil, serializer.NewError(serializer.CodeParamErr, "Invalid event categories", nil)
			}
			categories := []int{}
			for _, raw := range strings.Split(value, ",") {
				category, err := strconv.Atoi(strings.TrimSpace(raw))
				if err != nil || category < 0 || category > 61 {
					return nil, serializer.NewError(serializer.CodeParamErr, "Invalid event category", nil)
				}
				categories = append(categories, category)
			}
			q.Where(auditlog.TypeIn(categories...))
		default:
			return nil, serializer.NewError(serializer.CodeParamErr, "Unknown audit filter", nil)
		}
	}
	count, err := q.Clone().Count(c)
	if err != nil {
		return nil, err
	}
	orderBy := s.OrderBy
	if orderBy == "" {
		orderBy = auditlog.FieldID
	}
	if orderBy != auditlog.FieldID && orderBy != auditlog.FieldCreatedAt {
		return nil, serializer.NewError(serializer.CodeParamErr, "Invalid audit sort field", nil)
	}
	if s.OrderDirection != "" && s.OrderDirection != "desc" && s.OrderDirection != "asc" {
		return nil, serializer.NewError(serializer.CodeParamErr, "Invalid audit sort direction", nil)
	}
	if s.OrderDirection == "asc" {
		q.Order(ent.Asc(orderBy), ent.Asc(auditlog.FieldID))
	} else {
		q.Order(ent.Desc(orderBy), ent.Desc(auditlog.FieldID))
	}
	logs, err := q.Offset((s.Page - 1) * s.PageSize).Limit(s.PageSize).All(c)
	if err != nil {
		return nil, err
	}
	result, err := audit.BuildAdmin(c, dep.DBClient(), dep.HashIDEncoder(), logs)
	if err != nil {
		return nil, err
	}
	return &AuditListResponse{Logs: result, Pagination: &inventory.PaginationResults{Page: s.Page, PageSize: s.PageSize, TotalItems: count}}, nil
}

type SingleAuditLogService struct {
	ID int `uri:"id" binding:"required,min=1"`
}
type SingleAuditLogParamCtx struct{}

func (s *SingleAuditLogService) Get(c *gin.Context) (*audit.AdminLog, error) {
	dep := dependency.FromContext(c)
	log, err := dep.DBClient().AuditLog.Get(c, s.ID)
	if ent.IsNotFound(err) {
		return nil, serializer.NewError(serializer.CodeNotFound, "Audit event not found", nil)
	}
	if err != nil {
		return nil, err
	}
	result, err := audit.BuildAdmin(c, dep.DBClient(), dep.HashIDEncoder(), []*ent.AuditLog{log})
	if err != nil {
		return nil, err
	}
	return &result[0], nil
}
