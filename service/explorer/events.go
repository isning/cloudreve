package explorer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/constants"
	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth"
	"github.com/cloudreve/Cloudreve/v4/pkg/auth/requestinfo"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/eventhub"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

type (
	ExplorerEventService struct {
		Uri string `form:"uri" binding:"required"`
	}
	ExplorerEventParamCtx struct{}
	// EventStreamTickerCtx lets in-process callers provide a controlled ticker.
	// It is never populated from request parameters or headers.
	EventStreamTickerCtx struct{}
	EventStreamTicker    func(time.Duration) (<-chan time.Time, func())
)

func (s *ExplorerEventService) HandleExplorerEventsPush(c *gin.Context) error {
	dep := dependency.FromContext(c)
	user := inventory.UserFromContext(c)
	m := manager.NewFileManager(dep, user)
	l := logging.FromContext(c)
	defer m.Recycle()

	uri, err := fs.NewUriFromString(s.Uri)
	if err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Unknown uri", err)
	}

	if uri.SearchParameters() != nil {
		return serializer.NewError(serializer.CodeParamErr, "Search views do not support event subscriptions", nil)
	}

	// Make sure target is a valid folder that the user can listen to
	parent, listRes, err := m.List(c, uri, &manager.ListArgs{
		Page:     0,
		PageSize: 1,
	})
	if err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Requested uri not available", err)
	}

	// Reject event subscriptions on single-file views (e.g. single-file shares).
	// The listed parent is the underlying owner-side folder containing the file,
	// while the subscriber is only authorized to observe the shared file itself.
	// Subscribing to that folder topic would leak events about unshared siblings.
	if file, ok := parent.(*dbfs.File); !ok || !file.CanList() {
		return serializer.NewError(serializer.CodeNoPermissionErr, "Directory cannot be observed", nil)
	}
	if listRes != nil && listRes.SingleFileView {
		return serializer.NewError(serializer.CodeNoPermissionErr, "Event subscriptions are not supported on this view", nil)
	}

	requestInfo := requestinfo.RequestInfoFromContext(c)
	if requestInfo == nil || requestInfo.ClientID == "" {
		return serializer.NewError(serializer.CodeParamErr, "Client ID is required", nil)
	}

	// Client ID must be a valid UUID
	if _, err := uuid.FromString(requestInfo.ClientID); err != nil {
		return serializer.NewError(serializer.CodeParamErr, "Invalid client ID", err)
	}

	// A client UUID is not a bearer capability. Isolate native credentials,
	// the original entry URI (including link gate), and the canonical root.
	bearer := strings.TrimPrefix(c.GetHeader("Authorization"), auth.TokenHeaderPrefix)
	claims, err := dep.TokenAuth().Claims(c, bearer)
	if err != nil || claims.ExpiresAt == nil {
		return serializer.NewError(serializer.CodeCredentialInvalid, "Invalid stream credentials", nil)
	}
	tokenDigest := sha256.Sum256([]byte(bearer))
	key := uuid.NewV5(uuid.NamespaceOID, fmt.Sprintf("cloudreve-events/v1/%d/%x/%s/%s/%d/%d", user.ID, tokenDigest, requestInfo.ClientID, uri.String(), parent.OwnerID(), parent.ID())).String()
	access := &eventAccess{dep: dep, uid: user.ID, rootID: parent.ID(), ownerID: parent.OwnerID(), uri: uri, shared: uri.FileSystem() == constants.FileSystemShare, expires: claims.ExpiresAt.Time}
	subscribeCtx := eventhub.WithSubscriptionAccess(c.Request.Context(), eventhub.SubscriptionAccess{
		ClientID: requestInfo.ClientID,
		Filter: func(event *eventhub.Event) *eventhub.Event {
			filtered, err := access.filter(event)
			if err != nil {
				l.Debug("File event root authorization unavailable; subscriber %s", key)
			} else if filtered == nil {
				l.Debug("File event filtered by current authorization; subscriber %s", key)
			}
			return filtered
		},
	})
	// Subscribe
	eventHub := dep.EventHub()
	topic := parent.ID()
	rx, resumed, err := eventHub.Subscribe(subscribeCtx, topic, key)
	if err != nil {
		if errors.Is(err, eventhub.ErrSubscriberBusy) {
			return serializer.NewError(serializer.CodeLockConflict, "Event subscriber is busy; retry shortly", nil)
		}
		return serializer.NewError(serializer.CodeInternalSetting, "Failed to subscribe to events", err)
	}

	defer eventHub.Unsubscribe(context.Background(), topic, key)

	// SSE Headers
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	tickerFactory, _ := c.Value(EventStreamTickerCtx{}).(EventStreamTicker)
	if tickerFactory == nil {
		tickerFactory = func(d time.Duration) (<-chan time.Time, func()) {
			ticker := time.NewTicker(d)
			return ticker.C, ticker.Stop
		}
	}
	ticks, stopTicker := tickerFactory(30 * time.Second)
	defer stopTicker()
	expiry := time.NewTimer(max(0, time.Until(access.expires)))
	defer expiry.Stop()

	if resumed {
		c.SSEvent("resumed", nil)
		c.Writer.Flush()
	} else {
		c.SSEvent("subscribed", nil)
		c.Writer.Flush()
	}

	for {
		select {
		case <-expiry.C:
			l.Debug("File event credentials expired")
			return nil
		case <-c.Request.Context().Done():
			// Server shutdown or request cancelled
			l.Debug("Request context done, unsubscribed from event hub")
			return nil
		case <-c.Writer.CloseNotify():
			l.Debug("Unsubscribed from event hub")
			return nil
		case evt, ok := <-rx:
			if !ok {
				// Channel closed, EventHub is shutting down
				l.Debug("Event hub closed, disconnecting client")
				return nil
			}
			filtered, err := access.filter(evt)
			if err != nil {
				l.Debug("File event authorization changed; ending stream")
				return nil
			}
			if filtered == nil {
				continue
			}
			if filtered.Type == eventhub.EventTypeRefresh {
				c.SSEvent("refresh", map[string]any{})
			} else {
				c.SSEvent("event", filtered)
			}
			l.Debug("File event delivered")
			c.Writer.Flush()
			if c.Errors.Last() != nil {
				l.Error("Error occurred: %+v", c.Errors.Last().Error())
				l.Debug("Unsubscribed from event hub")
				return nil
			}
		case now := <-ticks:
			refresh, err := access.refreshRequired(now)
			if err != nil {
				l.Debug("File event root authorization changed; ending stream")
				return nil
			}
			if refresh {
				c.SSEvent("refresh", map[string]any{})
			}
			c.SSEvent("keep-alive", nil)
			c.Writer.Flush()
		}
	}
}
