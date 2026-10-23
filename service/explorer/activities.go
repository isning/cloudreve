package explorer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/ent/entity"
	entfile "github.com/cloudreve/Cloudreve/v4/ent/file"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
)

type FileActivitiesParamCtx struct{}
type FileActivitiesService struct {
	URI            string `form:"uri" binding:"required"`
	PageSize       int    `form:"page_size" binding:"required,min=10,max=500"`
	OrderDirection string `form:"order_direction" binding:"omitempty,oneof=asc desc"`
	NextPageToken  string `form:"next_page_token" binding:"max=4096"`
	Filter         string `form:"filter" binding:"omitempty,oneof=my updates reads"`
}

type ActivityContent struct {
	Category         types.AuditEvent `json:"category"`
	OriginalName     string           `json:"original_name,omitempty"`
	NewName          string           `json:"new_name,omitempty"`
	From             string           `json:"from,omitempty"`
	To               string           `json:"to,omitempty"`
	EntityCreateTime string           `json:"entity_create_time,omitempty"`
	StoragePolicyID  string           `json:"storage_policy_id,omitempty"`
	StoragePolicy    string           `json:"storage_policy,omitempty"`
	DirectLinkID     string           `json:"direct_link_id,omitempty"`
}

type Activity struct {
	ID        string          `json:"id"`
	Content   ActivityContent `json:"content"`
	CreatedAt time.Time       `json:"created_at"`
	User      map[string]any  `json:"user"`
	VersionID string          `json:"version_id,omitempty"`
}

type FileActivitiesResponse struct {
	Activities []Activity                   `json:"activities"`
	Pagination *inventory.PaginationResults `json:"pagination"`
}

type activityCursor struct {
	File      int    `json:"f"`
	Viewer    int    `json:"u"`
	After     int    `json:"a"`
	High      int    `json:"h"`
	Page      int    `json:"p"`
	Direction string `json:"d"`
	Filter    string `json:"k"`
}

func (s *FileActivitiesService) List(c *gin.Context) (*FileActivitiesResponse, error) {
	dep := dependency.FromContext(c)
	viewer := inventory.UserFromContext(c)
	m := manager.NewFileManager(dep, viewer)
	defer m.Recycle()
	uri, err := fs.NewUriFromString(s.URI)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeParamErr, "Invalid file URI", nil)
	}
	file, err := m.Get(c, uri, dbfs.WithRequiredCapabilities(dbfs.NavigatorCapabilityInfo))
	if err != nil {
		return nil, err
	}
	if viewer == nil || inventory.IsAnonymousUser(viewer) || (file.OwnerID() != viewer.ID && !file.Capabilities().Enabled(int(dbfs.NavigatorCapabilityRenameFile))) {
		return nil, serializer.NewError(serializer.CodeNoPermissionErr, "File activities require update permission", nil)
	}
	direction := s.OrderDirection
	if direction == "" {
		direction = "asc"
	}
	cursor := activityCursor{File: file.ID(), Viewer: viewer.ID, Direction: direction, Filter: s.Filter}
	if s.NextPageToken != "" {
		decoded, err := decodeActivityCursor(s.NextPageToken, dep.SettingProvider().SecretKey(c))
		if err != nil || decoded.File != file.ID() || decoded.Viewer != viewer.ID || decoded.Direction != direction || decoded.Filter != s.Filter {
			return nil, serializer.NewError(serializer.CodeParamErr, "Invalid activity page token", nil)
		}
		cursor = decoded
	}
	q := dep.DBClient().AuditLog.Query().Where(auditlog.FileID(file.ID()))
	switch s.Filter {
	case "my":
		q.Where(auditlog.UserID(viewer.ID))
	case "reads":
		q.Where(auditlog.TypeIn(int(types.AuditEntityDownloaded), int(types.AuditShareLinkViewed), int(types.AuditGetDirectLink)))
	case "updates":
		q.Where(auditlog.TypeNotIn(int(types.AuditEntityDownloaded), int(types.AuditShareLinkViewed), int(types.AuditGetDirectLink)))
	}
	result := &FileActivitiesResponse{Activities: []Activity{}, Pagination: &inventory.PaginationResults{Page: cursor.Page, PageSize: s.PageSize, IsCursor: true}}
	if s.NextPageToken == "" {
		last, err := q.Clone().Order(ent.Desc(auditlog.FieldID)).First(c)
		if ent.IsNotFound(err) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		cursor.High = last.ID
	}
	q.Where(auditlog.IDLTE(cursor.High))
	if direction == "asc" {
		if cursor.After > 0 {
			q.Where(auditlog.IDGT(cursor.After))
		}
		q.Order(ent.Asc(auditlog.FieldID))
	} else {
		if cursor.After > 0 {
			q.Where(auditlog.IDLT(cursor.After))
		}
		q.Order(ent.Desc(auditlog.FieldID))
	}
	logs, err := q.Limit(s.PageSize + 1).All(c)
	if err != nil {
		return nil, err
	}
	if len(logs) > s.PageSize {
		logs = logs[:s.PageSize]
		cursor.After, cursor.Page = logs[len(logs)-1].ID, cursor.Page+1
		result.Pagination.NextPageToken, err = encodeActivityCursor(cursor, dep.SettingProvider().SecretKey(c))
		if err != nil {
			return nil, err
		}
	}
	uids, eids := map[int]bool{}, map[int]bool{}
	for _, log := range logs {
		if log.UserID > 0 {
			uids[log.UserID] = true
		}
		if log.EntityID > 0 {
			eids[log.EntityID] = true
		}
	}
	users := map[int]map[string]any{}
	if len(uids) > 0 {
		ids := make([]int, 0, len(uids))
		for id := range uids {
			ids = append(ids, id)
		}
		actors, err := dep.DBClient().User.Query().Where(user.IDIn(ids...)).All(c)
		if err != nil {
			return nil, err
		}
		for _, actor := range actors {
			users[actor.ID] = map[string]any{"id": hashid.EncodeUserID(dep.HashIDEncoder(), actor.ID), "nickname": actor.Nick, "avatar": actor.Avatar, "created_at": actor.CreatedAt}
		}
	}
	versions := map[int]bool{}
	if len(eids) > 0 {
		ids := make([]int, 0, len(eids))
		for id := range eids {
			ids = append(ids, id)
		}
		rows, err := dep.DBClient().Entity.Query().Where(entity.IDIn(ids...), entity.HasFileWith(entfile.ID(file.ID()))).All(c)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			versions[row.ID] = true
		}
	}
	paths := map[string]string{}
	projectPath := func(raw string) string {
		if value, ok := paths[raw]; ok {
			return value
		}
		value := activityPath(c, raw, file, viewer.ID, dep.HashIDEncoder(), m)
		paths[raw] = value
		return value
	}
	for _, log := range logs {
		content := ActivityContent{Category: types.AuditEvent(log.Type)}
		if v := log.Content; v != nil {
			content.From = projectPath(v.From)
			content.To = projectPath(v.To)
			if file.OwnerID() == viewer.ID || (content.From != "" && content.From != "redacted") {
				content.OriginalName, content.NewName = v.OriginalName, v.NewName
			}
			content.EntityCreateTime = v.EntityCreateTime
			content.StoragePolicyID, content.StoragePolicy = v.StoragePolicyID, v.StoragePolicy
			if content.StoragePolicy == "" {
				content.StoragePolicy = v.StoragePolicyName
			}
			if file.OwnerID() == viewer.ID {
				content.DirectLinkID = v.DirectLinkID
			}
		}
		entry := Activity{ID: hashid.EncodeAuditLogID(dep.HashIDEncoder(), log.ID), Content: content, CreatedAt: log.CreatedAt, User: users[log.UserID]}
		if versions[log.EntityID] && (log.Type == int(types.AuditEntityUploaded) || log.Type == int(types.AuditSetCurrentVersion)) {
			entry.VersionID = hashid.EncodeEntityID(dep.HashIDEncoder(), log.EntityID)
		}
		result.Activities = append(result.Activities, entry)
	}
	return result, nil
}

func activityPath(ctx context.Context, raw string, file fs.File, viewerID int, encoder hashid.Encoder, m manager.FileManager) string {
	if raw == "" || raw == "redacted" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "cloudreve" {
		return "redacted"
	}
	owner := ""
	if u.User != nil {
		owner = u.User.Username()
	}
	if owner == hashid.EncodeUserID(encoder, viewerID) {
		return u.String()
	}
	if owner == hashid.EncodeUserID(encoder, file.OwnerID()) && file.OwnerID() != viewerID {
		if concrete, ok := file.(*dbfs.File); ok {
			root := concrete.UserRoot()
			if root != nil && root.Uri(true) != nil && root.Uri(false) != nil {
				prefix := root.Uri(true).Path()
				if u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/") {
					candidate := root.Uri(false).JoinRaw(strings.TrimPrefix(u.Path, prefix))
					visible, err := m.Get(ctx, candidate, dbfs.WithRequiredCapabilities(dbfs.NavigatorCapabilityInfo))
					// Historical paths carry no object identity. A different object at
					// the same path cannot prove access to the historical reference.
					if err == nil && visible.ID() == file.ID() && visible.OwnerID() == file.OwnerID() {
						if current, ok := visible.(*dbfs.File); ok && current.CanList() {
							return candidate.String()
						}
					}
				}
			}
		}
	}
	return "redacted"
}

func encodeActivityCursor(cursor activityCursor, key string) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func decodeActivityCursor(value, key string) (activityCursor, error) {
	var cursor activityCursor
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return cursor, fmt.Errorf("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return cursor, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cursor, err
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(raw)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return cursor, fmt.Errorf("invalid cursor signature")
	}
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return cursor, err
	}
	if cursor.After < 1 || cursor.High < cursor.After || cursor.Page < 1 {
		return cursor, fmt.Errorf("invalid cursor range")
	}
	return cursor, nil
}
