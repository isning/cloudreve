package relocation

import (
	"context"
	"errors"
	"math"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationitem"
	"github.com/cloudreve/Cloudreve/v4/ent/relocationplan"
)

// Progress is a public summary of durable facts, not the private transfer plan.
// Byte progress counts each entity at most once across owned attempts.
type Progress struct {
	Phase     string `json:"phase"`
	Total     int64  `json:"entities_total"`
	Completed int64  `json:"entities_completed"`
	Failed    int64  `json:"entities_failed"`
	Bytes     int64  `json:"bytes_total"`
	Copied    int64  `json:"bytes_copied"`
}

func ReadProgress(ctx context.Context, db *ent.Client, taskID int, failed bool) (*Progress, error) {
	items, err := db.RelocationItem.Query().Where(relocationitem.TaskID(taskID)).WithAttempts().All(ctx)
	if err != nil {
		return nil, errors.New("failed to load migration progress")
	}
	planned, err := db.RelocationPlan.Query().Where(relocationplan.TaskID(taskID)).Exist(ctx)
	if err != nil {
		return nil, errors.New("failed to load migration snapshot")
	}
	p := &Progress{Phase: "planning", Total: int64(len(items))}
	for _, item := range items {
		if item.Snapshot == nil || item.Snapshot.Size < 0 {
			return nil, errors.New("invalid migration progress snapshot")
		}
		if item.State == relocationitem.StateCommitted || item.State == relocationitem.StateNoop {
			p.Completed++
		}
		if item.State == relocationitem.StateFailed {
			failed = true
		}
		if item.State == relocationitem.StateNoop {
			continue
		}
		if math.MaxInt64-p.Bytes < item.Snapshot.Size {
			return nil, errors.New("migration progress size overflow")
		}
		p.Bytes += item.Snapshot.Size
		var copied int64
		for _, attempt := range item.Edges.Attempts {
			amount := attempt.TransferredSize
			// Existing verified journals predate persisted byte counters.
			if attempt.Verified && amount < attempt.VerifiedSize {
				amount = attempt.VerifiedSize
			}
			if amount > copied {
				copied = amount
			}
		}
		if copied > item.Snapshot.Size {
			copied = item.Snapshot.Size
		}
		p.Copied += copied
	}
	if planned || len(items) > 0 {
		p.Phase = "transferring"
		if p.Completed == p.Total {
			p.Phase = "completed"
		}
	}
	if failed {
		p.Phase = "failed"
		p.Failed = p.Total - p.Completed
	}
	return p, nil
}
