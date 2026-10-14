package relocation

import (
	"context"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
)

// Recheck current ancestry rather than the navigation snapshot: a parent can
// move into trash or change owner without rewriting every descendant row.
func validateLineage(ctx context.Context, db *ent.Client, file *ent.File, ownerID int) error {
	seen := make(map[int]bool)
	for {
		if file == nil || seen[file.ID] || file.OwnerID != ownerID || file.IsSymbolic || (file.Type != int(types.FileTypeFile) && file.Type != int(types.FileTypeFolder)) {
			return ErrConflict
		}
		seen[file.ID] = true
		if file.FileChildren == 0 {
			if file.Type != int(types.FileTypeFolder) || file.Name != inventory.RootFolderName {
				return ErrConflict
			}
			return nil
		}
		parent, err := db.File.Get(ctx, file.FileChildren)
		if err != nil || parent.Type != int(types.FileTypeFolder) {
			return ErrConflict
		}
		file = parent
	}
}
