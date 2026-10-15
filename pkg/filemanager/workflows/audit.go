package workflows

import (
	"context"
	"net/url"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
)

// ArchiveAuditSource is captured from the object actually consumed, then saved
// with workflow state. A path can refer to a different object by completion.
type ArchiveAuditSource struct {
	FileID int    `json:"file_id"`
	URI    string `json:"uri"`
}

func archiveSource(file fs.File, encoder hashid.Encoder) ArchiveAuditSource {
	source := ArchiveAuditSource{FileID: file.ID(), URI: "redacted"}
	if uri := file.Uri(true); uri != nil && uri.U != nil {
		canonical := *uri.U
		canonical.User = url.User(hashid.EncodeUserID(encoder, file.OwnerID()))
		source.URI = canonical.String()
	}
	return source
}

// CompletionAudit is persisted with the native task's completed transition, so
// retries and a worker restart cannot duplicate successful archive operations.
func (m *CreateArchiveTask) CompletionAudit(ctx context.Context) []inventory.AuditEvent {
	return archiveAudit(ctx, types.AuditCreateArchive, m.state.AuditSources, m.state.Uris, m.state.Dst)
}
func (m *ExtractArchiveTask) CompletionAudit(ctx context.Context) []inventory.AuditEvent {
	var sources []ArchiveAuditSource
	if m.state.AuditSource != nil {
		sources = []ArchiveAuditSource{*m.state.AuditSource}
	}
	return archiveAudit(ctx, types.AuditExtractArchive, sources, []string{m.state.Uri}, m.state.Dst)
}
func archiveAudit(ctx context.Context, kind types.AuditEvent, sources []ArchiveAuditSource, legacySources []string, destination string) []inventory.AuditEvent {
	dep := dependency.FromContext(ctx)
	actor := inventory.UserFromContext(ctx)
	if actor == nil {
		return nil
	}
	canonical := func(raw string) string {
		u, err := fs.NewUriFromString(raw)
		if err != nil {
			return "redacted"
		}
		u.U.User = url.User(hashid.EncodeUserID(dep.HashIDEncoder(), actor.ID))
		return u.String()
	}
	if sources == nil {
		// Tasks already past source consumption before this upgrade have no object
		// snapshot. Preserve their paths without guessing IDs from today's objects.
		for _, raw := range legacySources {
			sources = append(sources, ArchiveAuditSource{URI: canonical(raw)})
		}
	}
	result := make([]inventory.AuditEvent, 0, len(sources))
	for _, source := range sources {
		entry := inventory.AuditEvent{Type: kind, User: actor, FileID: source.FileID, Content: types.LogEntry{From: source.URI, To: canonical(destination)}}
		result = append(result, entry)
	}
	return result
}
