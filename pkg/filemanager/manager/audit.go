package manager

import (
	"context"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/audit"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"net/url"
)

func (m *manager) recordFileAudit(ctx context.Context, kind types.AuditEvent, file fs.File, entityID int, content types.LogEntry) error {
	if uri := file.Uri(true); content.From == "" && uri != nil && uri.U != nil {
		u := *uri.U
		u.User = url.User(hashid.EncodeUserID(m.hasher, file.OwnerID()))
		content.From = u.String()
	}
	actor := inventory.UserFromContext(ctx)
	if actor == nil && requestinfo.RequestInfoFromContext(ctx) == nil {
		actor = m.user
	}
	return audit.New(m.dep.DBClient(), m.settings, m.l).Record(ctx, audit.Event{Type: kind, User: actor, FileID: file.ID(), EntityID: entityID, Content: content})
}
