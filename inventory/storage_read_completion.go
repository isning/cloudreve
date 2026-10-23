package inventory

import (
	"context"
	"sync"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
)

type completedStorageRead struct {
	id      int
	attempt bool
}

// StorageReadCompletions retains actual local completion evidence across SQL
// outages. It never infers completion from leases, elapsed time or startup.
// Evidence not persisted before process death remains conservatively unfinished.
type StorageReadCompletions struct {
	db      *ent.Client
	logger  logging.Logger
	mu      sync.Mutex
	pending map[completedStorageRead]struct{}
	wake    chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewStorageReadCompletions(db *ent.Client, logger logging.Logger) *StorageReadCompletions {
	ctx, cancel := context.WithCancel(context.Background())
	r := &StorageReadCompletions{db: db, logger: logger, pending: make(map[completedStorageRead]struct{}), wake: make(chan struct{}, 1), cancel: cancel, done: make(chan struct{})}
	go r.run(ctx)
	return r
}

func (r *StorageReadCompletions) ReaderFinished(id int) { r.record(completedStorageRead{id: id}) }
func (r *StorageReadCompletions) AttemptSourceFinished(id int) {
	r.record(completedStorageRead{id: id, attempt: true})
}

func (r *StorageReadCompletions) persist(ctx context.Context, fact completedStorageRead) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if fact.attempt {
		return r.db.RelocationAttempt.UpdateOneID(fact.id).SetSourceReadFinished(true).Exec(ctx)
	}
	return r.db.StorageObjectReader.UpdateOneID(fact.id).SetFinished(true).Exec(ctx)
}

func (r *StorageReadCompletions) record(fact completedStorageRead) {
	if r.persist(context.Background(), fact) == nil {
		return
	}
	r.mu.Lock()
	r.pending[fact] = struct{}{}
	r.mu.Unlock()
	r.logger.Warning("Migration read completion deferred; its storage dependency is retained")
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *StorageReadCompletions) flush(ctx context.Context) bool {
	r.mu.Lock()
	facts := make([]completedStorageRead, 0, len(r.pending))
	for fact := range r.pending {
		facts = append(facts, fact)
	}
	r.mu.Unlock()
	for _, fact := range facts {
		if ctx.Err() != nil {
			break
		}
		if r.persist(ctx, fact) == nil {
			r.mu.Lock()
			delete(r.pending, fact)
			r.mu.Unlock()
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending) == 0
}

func (r *StorageReadCompletions) run(ctx context.Context) {
	defer close(r.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		}
		for !r.flush(ctx) {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

// Close runs after queue consumers have drained, before closing the database.
func (r *StorageReadCompletions) Close(ctx context.Context) {
	r.cancel()
	<-r.done
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if !r.flush(ctx) {
		r.logger.Warning("Migration read completion remains unacknowledged at shutdown; journal retained")
	}
}
