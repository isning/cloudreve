package dbfs

import (
	"context"
	"net/url"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/audit"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
)

func (f *DBFS) recordAuditModel(ctx context.Context, kind types.AuditEvent, file *ent.File, uri *fs.URI, content types.LogEntry, entityID int) error {
	if f.audit == nil {
		return nil
	}
	if content.Name == "" {
		content.Name = file.Name
	}
	if content.From == "" && uri != nil && uri.U != nil {
		content.From = auditURI(uri, file.OwnerID, f.hasher)
	}
	actor := f.user
	if requester := inventory.UserFromContext(ctx); requester != nil {
		actor = requester
	}
	return f.audit.Record(ctx, audit.Event{Type: kind, User: actor, FileID: file.ID, EntityID: entityID, Content: content})
}

func (f *DBFS) recordAudit(ctx context.Context, kind types.AuditEvent, file *File, content types.LogEntry, entityID int) error {
	return f.recordAuditModel(ctx, kind, file.Model, file.Uri(true), content, entityID)
}

func auditURI(uri *fs.URI, owner int, encoder hashid.Encoder) string {
	if uri == nil || uri.U == nil {
		return ""
	}
	copy := *uri.U
	copy.User = url.User(hashid.EncodeUserID(encoder, owner))
	return copy.String()
}
