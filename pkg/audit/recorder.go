// Package audit records durable, allowlisted domain operations independently
// of the debounced filesystem notification stream.
package audit

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/gofrs/uuid"
)

type Event = inventory.AuditEvent

type Recorder struct {
	client   *ent.Client
	settings setting.Provider
	logger   logging.Logger
}

func New(client *ent.Client, settings setting.Provider, logger logging.Logger) *Recorder {
	return &Recorder{client: client, settings: settings, logger: logger}
}

func WithRecorder(ctx context.Context, recorder *Recorder) context.Context {
	return inventory.WithAuditRecorder(ctx, recorder)
}

func FromContext(ctx context.Context) *Recorder {
	r, _ := inventory.AuditRecorderFromContext(ctx).(*Recorder)
	return r
}

// Detach copies only the metadata needed by delayed side effects. In particular,
// a pooled gin.Context and the request body must never escape their request.
func Detach(ctx context.Context) context.Context {
	result := context.Background()
	if recorder := FromContext(ctx); recorder != nil {
		result = WithRecorder(result, recorder)
	}
	if actor := inventory.UserFromContext(ctx); actor != nil {
		result = context.WithValue(result, inventory.UserCtx{}, &ent.User{ID: actor.ID})
	}
	if info := requestinfo.RequestInfoFromContext(ctx); info != nil {
		copy := *info
		result = context.WithValue(result, requestinfo.RequestInfoCtx{}, &copy)
	}
	if cid := ctx.Value(logging.CorrelationIDCtx{}); cid != nil {
		result = context.WithValue(result, logging.CorrelationIDCtx{}, cid)
	}
	return result
}

func (r *Recorder) WithClient(client *ent.Client) inventory.AuditRecorder {
	copy := *r
	copy.client = client
	return &copy
}

// Record participates in an inherited inventory transaction when present.
// Callers that mutate data use this before their commit and propagate errors.
func (r *Recorder) Record(ctx context.Context, event Event) error {
	if r == nil || event.Type < 0 || event.Type > types.AuditOAuthGrantRevoke {
		return nil
	}
	config := r.settings.Audit(ctx)
	if config.Enabled == nil || !config.Enabled.Enabled(int(event.Type)) {
		return nil
	}
	client, _ := inventory.InheritTx(ctx, &auditClient{client: r.client})
	ctx = context.WithValue(ctx, debug.SkipDbLogging{}, true)
	content := event.Content
	content.Category = event.Type
	content.From, content.To = cleanURI(content.From), cleanURI(content.To)
	content.AccountURI = cleanURI(content.AccountURI)
	content.Account = bounded(content.Account, 512)
	content.Sub = bounded(content.Sub, 1024)
	content.Reason = bounded(content.Reason, 256)
	content.Name = bounded(content.Name, 512)
	content.OriginalName, content.NewName = bounded(content.OriginalName, 512), bounded(content.NewName, 512)
	content.EmailTo, content.EmailTitle = bounded(content.EmailTo, 512), bounded(content.EmailTitle, 1024)
	if content.Error != "" {
		content.Error = "operation failed"
		content.Failed = true
	}
	var ip, correlation string
	if info := requestinfo.RequestInfoFromContext(ctx); info != nil {
		content.UserAgent = bounded(info.UserAgent, 1024)
		if config.RecordIP && net.ParseIP(info.IP) != nil {
			ip = info.IP
		}
	}
	if id, ok := ctx.Value(logging.CorrelationIDCtx{}).(uuid.UUID); ok {
		correlation = id.String()
	}
	actor := event.User
	if actor == nil {
		actor = inventory.UserFromContext(ctx)
	}
	uid := 0
	if actor != nil && !inventory.IsAnonymousUser(actor) {
		uid = actor.ID
	}
	if uid == 0 && requestinfo.RequestInfoFromContext(ctx) == nil {
		content.IsSystem = true
	}
	create := client.client.AuditLog.Create().SetCreatedAt(time.Now().UTC()).SetType(int(event.Type)).SetUserID(uid).
		SetFileID(event.FileID).SetEntityID(event.EntityID).SetShareID(event.ShareID).
		SetCorrelationID(correlation).SetIP(ip).SetContent(&content)
	if err := create.Exec(ctx); err != nil {
		return fmt.Errorf("persist audit event %d: %w", event.Type, err)
	}
	return nil
}

// Record is a no-op only for contexts with no audit recorder (for example slave
// operations that report their committed result to the master).
func Record(ctx context.Context, event Event) error { return FromContext(ctx).Record(ctx, event) }

// Observe records a read or a completed operation. Storage errors remain
// observable in operational logs without leaking the event payload.
func Observe(ctx context.Context, event Event) {
	if r := FromContext(ctx); r != nil {
		if err := r.Record(ctx, event); err != nil {
			r.logger.Error("Failed to persist audit event %d: %v", event.Type, err)
		}
	}
}

type auditClient struct{ client *ent.Client }

func (c *auditClient) GetClient() *ent.Client { return c.client }
func (c *auditClient) SetClient(client *ent.Client) inventory.TxOperator {
	return &auditClient{client: client}
}

func cleanURI(value string) string {
	if value == "" || value == "redacted" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil {
		return "redacted"
	}
	u.RawQuery, u.Fragment = "", ""
	if u.Scheme == "http" || u.Scheme == "https" {
		u.User = nil
	} else if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	if value := u.String(); len(value) <= 4096 {
		return value
	}
	return "redacted"
}

func bounded(value string, limit int) string {
	value = strings.ToValidUTF8(value, "")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
