package manager

import (
	"context"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/filemanager/fs"
)

// backgroundFileTarget gives derived tasks the receiver's identity and canonical
// path. Visitor credentials and expiring share URLs are request capabilities,
// not durable worker identities. The original context still identifies the actor.
func (m *manager) backgroundFileTarget(ctx context.Context, fileID, ownerID int) (*ent.User, *fs.URI, error) {
	owner, err := m.dep.UserClient().GetByID(context.WithValue(ctx, inventory.LoadUserGroup{}, true), ownerID)
	if err != nil {
		return nil, nil, err
	}
	fm := NewFileManager(m.dep, owner)
	defer fm.Recycle()
	file, err := fm.TraverseFile(ctx, fileID)
	if err != nil {
		return nil, nil, err
	}
	if file.OwnerID() != ownerID {
		return nil, nil, fmt.Errorf("background file owner changed")
	}
	return owner, file.Uri(true), nil
}
