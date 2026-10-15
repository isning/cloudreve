package workflows

import (
	"context"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/stretchr/testify/require"
)

func TestArchiveAuditWithoutLegacySnapshotNeverGuessesAnObject(t *testing.T) {
	encoder, err := hashid.New("audit-legacy-workflow")
	require.NoError(t, err)
	dep := dependency.NewDependency(dependency.WithHashIDEncoder(encoder))
	ctx := context.WithValue(context.Background(), dependency.DepCtx{}, dep)
	ctx = context.WithValue(ctx, inventory.UserCtx{}, &ent.User{ID: 2})
	archive := &CreateArchiveTask{state: &CreateArchiveTaskState{Uris: []string{"cloudreve://my/source.txt"}, Dst: "cloudreve://my/result.zip"}}
	extract := &ExtractArchiveTask{state: &ExtractArchiveTaskState{Uri: "cloudreve://my/source.zip", Dst: "cloudreve://my/output"}}
	for _, events := range [][]inventory.AuditEvent{archive.CompletionAudit(ctx), extract.CompletionAudit(ctx)} {
		require.Len(t, events, 1)
		require.Zero(t, events[0].FileID)
		require.Contains(t, events[0].Content.From, "source.")
		require.Equal(t, 2, events[0].User.ID)
		require.Contains(t, []types.AuditEvent{types.AuditCreateArchive, types.AuditExtractArchive}, events[0].Type)
	}
}
