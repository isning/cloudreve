package relocation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/pkg/request"
)

var ErrRetryableIO = errors.New("migration I/O temporarily unavailable")
var ErrJournalUnavailable = errors.New("migration journal acknowledgement temporarily unavailable")

func retryableIO(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	retryStatus := func(code int) bool { return code == 401 || code == 403 || code == 408 || code == 429 || code >= 500 }
	var remote request.UnexpectedStatusError
	if errors.As(err, &remote) {
		return retryStatus(int(remote))
	}
	var provider awserr.RequestFailure
	if errors.As(err, &provider) {
		return retryStatus(provider.StatusCode())
	}
	var network net.Error
	return (errors.As(err, &network) && network.Timeout()) || os.IsPermission(err)
}

func providerRejectedWrite(err error) bool {
	var provider awserr.RequestFailure
	return errors.As(err, &provider) && provider.StatusCode() >= 400 && provider.StatusCode() < 500 && provider.StatusCode() != 408
}

func releaseIOFailure(ctx context.Context, db *ent.Client, item *ent.RelocationItem) error {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	builder := db.RelocationItem.Update().Where(relocationitem.ID(item.ID), relocationitem.Fence(item.Fence), relocationitem.LeaseOwner(item.LeaseOwner), relocationitem.LeaseUntilGT(time.Now()), relocationitem.StateNotIn(relocationitem.StateCommitted, relocationitem.StateNoop, relocationitem.StateFailed)).SetLeaseOwner("").ClearLeaseUntil().SetError(ErrRetryableIO.Error()).SetSourceCleanup(relocationitem.SourceCleanupPending)
	if item.State != relocationitem.StateVerified {
		builder.SetState(relocationitem.StatePlanned)
	}
	n, err := builder.Save(recordCtx)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrLeaseLost
	}
	return ErrRetryableIO
}

// Terminal failure closes only unclaimed work. Another worker's current lease
// and committed facts cannot be overwritten by an older invocation.
func FailUnclaimed(ctx context.Context, db *ent.Client, taskID int) error {
	_, err := db.RelocationItem.Update().Where(relocationitem.TaskID(taskID), relocationitem.LeaseOwner(""), relocationitem.StateIn(relocationitem.StatePlanned, relocationitem.StateVerified)).SetState(relocationitem.StateFailed).SetError("migration ended before this item completed").Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to persist unclaimed migration failure")
	}
	return nil
}
