package admin

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/auditarchive"
	"github.com/cloudreve/Cloudreve/v4/ent/auditarchiveitem"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/ent/predicate"
	"github.com/cloudreve/Cloudreve/v4/ent/schema"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/audit"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

type BatchAuditLogService struct {
	IDs []int `json:"ids" binding:"required,min=1,max=500,dive,min=1"`
}
type BatchAuditLogParamCtx struct{}

func (s *BatchAuditLogService) Delete(c *gin.Context) error {
	_, err := dependency.FromContext(c).DBClient().AuditLog.Delete().Where(auditlog.IDIn(s.IDs...)).Exec(schema.SkipSoftDelete(c))
	return err
}

type CleanupAuditLogService struct {
	NotAfter   time.Time `json:"not_after" binding:"required"`
	Categories []int     `json:"categories" binding:"max=62,dive,min=0,max=61"`
}
type CleanupAuditLogParamCtx struct{}

func (s *CleanupAuditLogService) Cleanup(c *gin.Context) error {
	q := dependency.FromContext(c).DBClient().AuditLog.Delete().Where(auditlog.CreatedAtLTE(s.NotAfter.UTC()))
	if len(s.Categories) > 0 {
		q.Where(auditlog.TypeIn(s.Categories...))
	}
	_, err := q.Exec(schema.SkipSoftDelete(c))
	return err
}

type CreateAuditArchiveService struct {
	NotBefore  time.Time `json:"not_before" binding:"required"`
	NotAfter   time.Time `json:"not_after" binding:"required"`
	Categories []int     `json:"categories" binding:"max=62,dive,min=0,max=61"`
}
type CreateAuditArchiveParamCtx struct{}
type AuditArchiveResponse struct {
	ID      string    `json:"id"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}
type AuditArchiveService struct {
	ID string `uri:"id" binding:"required,uuid"`
}
type AuditArchiveParamCtx struct{}

func (s *CreateAuditArchiveService) Create(c *gin.Context) (*AuditArchiveResponse, error) {
	if s.NotBefore.After(s.NotAfter) {
		return nil, serializer.NewError(serializer.CodeParamErr, "Invalid audit date range", nil)
	}
	dep := dependency.FromContext(c)
	ctx := context.WithValue(c, debug.SkipDbLogging{}, true)
	client := dep.DBClient()
	if err := cleanupExpiredAuditArchives(ctx, client); err != nil {
		return nil, err
	}
	high := 0
	last, err := client.AuditLog.Query().Order(ent.Desc(auditlog.FieldID)).First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	if last != nil {
		high = last.ID
	}
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	raw := hex.EncodeToString(token)
	hash := sha256.Sum256([]byte(raw))
	expires := time.Now().UTC().Add(time.Hour)
	if err := client.AuditArchive.Create().SetArchiveKey(id.String()).SetOwnerID(inventory.UserIDFromContext(c)).
		SetTokenHash(hex.EncodeToString(hash[:])).SetNotBefore(s.NotBefore.UTC()).SetNotAfter(s.NotAfter.UTC()).
		SetCategories(s.Categories).SetHighID(high).SetExpires(expires).Exec(ctx); err != nil {
		return nil, err
	}
	u := *dep.SettingProvider().SiteURL(c)
	u.Path = path.Join(u.Path, "api/v4/audit/archive", id.String())
	query := u.Query()
	query.Set("token", raw)
	u.RawQuery = query.Encode()
	return &AuditArchiveResponse{ID: id.String(), URL: u.String(), Expires: expires}, nil
}

func (s *AuditArchiveService) Status(c *gin.Context) (map[string]string, error) {
	client := dependency.FromContext(c).DBClient()
	row, err := client.AuditArchive.Query().Where(auditarchive.ArchiveKey(s.ID)).Only(c)
	if ent.IsNotFound(err) {
		return nil, serializer.NewError(serializer.CodeNotFound, "Audit archive not found", nil)
	}
	if err != nil {
		return nil, err
	}
	status := row.Status
	if status == "processing" && time.Since(row.UpdatedAt) > 5*time.Minute {
		n, err := client.AuditArchive.Update().Where(auditarchive.ID(row.ID), auditarchive.Status("processing"), auditarchive.UpdatedAtLTE(time.Now().UTC().Add(-5*time.Minute))).SetStatus("failed").SetUpdatedAt(time.Now().UTC()).Save(c)
		if err != nil {
			return nil, err
		}
		if n == 1 {
			status = "failed"
		}
	}
	if !row.Expires.After(time.Now()) || status == "failed" {
		status = "failed"
	} else if status == "processing" {
		status = "pending"
	} else if status == "purged" {
		status = "completed"
	}
	return map[string]string{"status": status}, nil
}

// Purge uses actual export membership, never a re-evaluated date predicate.
func (s *AuditArchiveService) Purge(c *gin.Context) error {
	dep := dependency.FromContext(c)
	fc, tx, ctx, err := inventory.WithTx(c, dep.FileClient())
	if err != nil {
		return err
	}
	defer inventory.Rollback(tx)
	client := fc.GetClient()
	n, err := client.AuditArchive.Update().Where(auditarchive.ArchiveKey(s.ID), auditarchive.Status("completed"), auditarchive.ExpiresGT(time.Now().UTC())).SetStatus("purged").Save(ctx)
	if err != nil {
		return err
	}
	if n != 1 {
		return serializer.NewError(serializer.CodeConflict, "Audit export has not completed or has expired", nil)
	}
	_, err = client.AuditLog.Delete().Where(exportedAuditIDs(s.ID)).Exec(schema.SkipSoftDelete(ctx))
	if err != nil {
		return err
	}
	return inventory.Commit(tx)
}

func exportedAuditIDs(id string) predicate.AuditLog {
	return func(s *sql.Selector) {
		t := sql.Table(auditarchiveitem.Table)
		s.Where(sql.In(s.C(auditlog.FieldID), sql.Select(t.C(auditarchiveitem.FieldLogID)).From(t).Where(sql.EQ(t.C(auditarchiveitem.FieldArchiveID), id))))
	}
}

// Download is a one-use capability URL because the Pro client loads it in an
// iframe without Authorization headers. Tokens are hashed and expire in one hour.
func (s *AuditArchiveService) Download(c *gin.Context) error {
	dep := dependency.FromContext(c)
	ctx := context.WithValue(c, debug.SkipDbLogging{}, true)
	client := dep.DBClient()
	row, err := client.AuditArchive.Query().Where(auditarchive.ArchiveKey(s.ID)).Only(ctx)
	if err != nil {
		return serializer.NewError(serializer.CodeNotFound, "Audit archive not found", nil)
	}
	hash := sha256.Sum256([]byte(c.Query("token")))
	if subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(hex.EncodeToString(hash[:]))) != 1 || !row.Expires.After(time.Now()) {
		return serializer.NewError(serializer.CodeNoPermissionErr, "Audit download authorization expired", nil)
	}
	ctx, cancel := context.WithDeadline(ctx, row.Expires)
	defer cancel()
	owner, err := dep.UserClient().GetActiveByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), row.OwnerID)
	if err != nil || owner.Edges.Group == nil || owner.Edges.Group.Permissions == nil || !owner.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin)) {
		return serializer.NewError(serializer.CodeNoPermissionErr, "Audit download authorization revoked", nil)
	}
	n, err := client.AuditArchive.Update().Where(auditarchive.ArchiveKey(s.ID), auditarchive.Status("pending"), auditarchive.ExpiresGT(time.Now().UTC())).SetStatus("processing").SetUpdatedAt(time.Now().UTC()).Save(ctx)
	if err != nil {
		return err
	}
	if n != 1 {
		return serializer.NewError(serializer.CodeConflict, "Audit download already started", nil)
	}
	completed := false
	defer func() {
		if !completed {
			failCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.AuditArchive.UpdateOneID(row.ID).SetStatus("failed").Exec(failCtx)
		}
	}()
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-%s.ndjson.gz"`, row.ArchiveKey))
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(http.StatusOK)
	zip := gzip.NewWriter(c.Writer)
	encoder := json.NewEncoder(zip)
	after := 0
	for {
		q := client.AuditLog.Query().Where(auditlog.IDGT(after), auditlog.IDLTE(row.HighID), auditlog.CreatedAtGTE(row.NotBefore), auditlog.CreatedAtLTE(row.NotAfter)).Order(ent.Asc(auditlog.FieldID)).Limit(200)
		if len(row.Categories) > 0 {
			q.Where(auditlog.TypeIn(row.Categories...))
		}
		logs, err := q.All(ctx)
		if err != nil {
			return err
		}
		if len(logs) == 0 {
			break
		}
		entries, err := audit.BuildAdmin(ctx, client, dep.HashIDEncoder(), logs)
		if err != nil {
			return err
		}
		items := make([]*ent.AuditArchiveItemCreate, 0, len(logs))
		for _, entry := range entries {
			if err := encoder.Encode(entry); err != nil {
				return err
			}
			items = append(items, client.AuditArchiveItem.Create().SetArchiveID(row.ArchiveKey).SetLogID(entry.ID))
		}
		if err := client.AuditArchiveItem.CreateBulk(items...).Exec(ctx); err != nil {
			return err
		}
		if err := client.AuditArchive.UpdateOneID(row.ID).SetStatus("processing").SetUpdatedAt(time.Now().UTC()).Where(auditarchive.Status("processing")).Exec(ctx); err != nil {
			return err
		}
		after = logs[len(logs)-1].ID
	}
	if err := zip.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.AuditArchive.UpdateOneID(row.ID).Where(auditarchive.Status("processing"), auditarchive.ExpiresGT(time.Now().UTC())).SetStatus("completed").SetUpdatedAt(time.Now().UTC()).Exec(ctx); err != nil {
		return err
	}
	completed = true
	return nil
}

func cleanupExpiredAuditArchives(ctx context.Context, client *ent.Client) error {
	ids, err := client.AuditArchive.Query().Where(auditarchive.ExpiresLTE(time.Now().UTC())).Limit(500).Select(auditarchive.FieldArchiveKey).Strings(ctx)
	if err != nil || len(ids) == 0 {
		return err
	}
	if _, err := client.AuditArchiveItem.Delete().Where(auditarchiveitem.ArchiveIDIn(ids...)).Exec(ctx); err != nil {
		return err
	}
	_, err = client.AuditArchive.Delete().Where(auditarchive.ArchiveKeyIn(ids...)).Exec(schema.SkipSoftDelete(ctx))
	return err
}
