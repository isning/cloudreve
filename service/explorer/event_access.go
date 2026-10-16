package explorer

import (
	"context"
	"path"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/debug"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/eventhub"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs/dbfs"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/manager"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
)

// eventAccess retains immutable entry identifiers, never a pooled Gin context or
// a cached file/user grant. The same check protects enqueue and replay output.
type eventAccess struct {
	dep                  dependency.Dep
	uid, rootID, ownerID int
	uri                  *fs.URI
	shared               bool
	expires              time.Time
}

func (a *eventAccess) current(now time.Time) (manager.FileManager, context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ctx = context.WithValue(ctx, logging.LoggerCtx{}, a.dep.Logger())
	// These detached checks traverse event paths the recipient may not know.
	// SQL debug arguments must not turn a filtered event into a log disclosure.
	ctx = context.WithValue(ctx, debug.SkipDbLogging{}, true)
	if !now.Before(a.expires) {
		cancel()
		return nil, nil, func() {}, dbfs.ErrPermissionDenied
	}
	user, err := a.dep.UserClient().GetLoginUserByID(ctx, a.uid)
	if err != nil {
		cancel()
		return nil, nil, func() {}, err
	}
	ctx = context.WithValue(ctx, inventory.UserCtx{}, user)
	m := manager.NewFileManager(a.dep, user)
	done := func() { m.Recycle(); cancel() }
	root, err := m.Get(ctx, a.uri, dbfs.WithRequiredCapabilities(dbfs.NavigatorCapabilityInfo))
	if err != nil {
		done()
		return nil, nil, func() {}, err
	}
	file, ok := root.(*dbfs.File)
	if !ok || !file.CanList() || file.ID() != a.rootID || file.OwnerID() != a.ownerID {
		done()
		return nil, nil, func() {}, dbfs.ErrPermissionDenied
	}
	return m, ctx, done, nil
}
func (a *eventAccess) refreshRequired(now time.Time) (bool, error) {
	_, ctx, done, err := a.current(now)
	defer done()
	if err != nil {
		return false, err
	}
	return a.restricted(ctx), nil
}

func (a *eventAccess) restricted(ctx context.Context) bool {
	actor := inventory.UserFromContext(ctx)
	return a.shared && actor.ID != a.ownerID && !actor.Edges.Group.Permissions.Enabled(int(types.GroupPermissionIsAdmin))
}

func (a *eventAccess) filter(event *eventhub.Event) (*eventhub.Event, error) {
	m, ctx, done, err := a.current(time.Now())
	if err != nil {
		return nil, err
	}
	defer done()
	if event.Type == eventhub.EventTypeRefresh {
		return &eventhub.Event{Type: eventhub.EventTypeRefresh}, nil
	}
	// Re-evaluate the role on each delivery, so losing administrator status
	// cannot preserve a privileged stream or bypass descendant filtering.
	if !a.restricted(ctx) {
		copy := *event
		return &copy, nil
	}
	visible := func(relative string) bool {
		if relative == "" || relative == "/" || path.Clean(relative) != relative || relative[0] != '/' {
			return false
		}
		file, err := m.Get(ctx, a.uri.JoinRaw(relative), dbfs.WithRequiredCapabilities(dbfs.NavigatorCapabilityInfo))
		if err != nil {
			return false
		}
		target, ok := file.(*dbfs.File)
		return ok && target.CanList() && hashid.EncodeFileID(a.dep.HashIDEncoder(), file.ID()) == event.FileID
	}
	switch event.Type {
	case eventhub.EventTypeCreate, eventhub.EventTypeModify:
		if visible(event.From) {
			copy := *event
			copy.To = ""
			return &copy, nil
		}
	case eventhub.EventTypeRename:
		// Historical names cannot prove an old ACL. Only reveal a currently
		// visible arrival; the periodic, data-free refresh removes old rows.
		if visible(event.To) {
			return &eventhub.Event{Type: eventhub.EventTypeCreate, FileID: event.FileID, From: event.To}, nil
		}
	}
	return nil, nil
}
