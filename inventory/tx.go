package inventory

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
)

type TxOperator interface {
	SetClient(newClient *ent.Client) TxOperator
	GetClient() *ent.Client
}

type (
	Tx struct {
		tx *ent.Tx
		// baseClient supplies committed metadata before lifecycle locks.
		baseClient                      *ent.Client
		parent                          *Tx
		inherited                       bool
		finished                        bool
		committed                       bool
		afterCommit                     []func()
		storageDiff                     StorageDiff
		permissionOwners                map[int]bool
		defaultShareConfigurationLocked bool
	}

	// TxCtx is the context key for inherited transaction
	TxCtx struct{}
)

// ReserveStorage atomically adds `size` bytes to user `uid`'s storage inside
// this transaction, enforcing storage + size <= maxTotal at the database
// level (when maxTotal > 0). This is the correct API for grabbing the
// per-user storage quota:
//
//   - It MUST be called as the first write of the transaction (or at least
//     before any other WRITE to files/entities/etc.). That way the users-row
//     X lock is acquired before any INSERT into files/entities, so
//     concurrent uploads for the same owner serialize on the users row from
//     the start and cannot deadlock via foreign-key S locks on the shared
//     parent folder / storage-policy rows.
//   - A matching compensating negative diff is appended to storageDiff so
//     the pre-reservation is netted against the positive diff emitted later
//     by CreateEntity / fc.Copy / etc. No amount is double-applied.
//   - On failure (quota exceeded or any other DB error) the caller MUST
//     Rollback the transaction: any placeholder writes done afterwards
//     would otherwise be committed without a matching storage reservation.
//
// It is safe to call this from an inherited-tx wrapper (returned by
// InheritTx) — AppendStorageDiff routes to the root tx.
func (t *Tx) ReserveStorage(ctx context.Context, uc UserClient, uid int, size, maxTotal int64) error {
	if size <= 0 {
		return nil
	}

	txUc, _ := InheritTx(ctx, uc)
	if err := txUc.ReserveStorage(ctx, uid, size, maxTotal); err != nil {
		return err
	}

	// Net out the pre-reservation against any positive diff that
	// CreateEntity / fc.Copy / ... will append later in the same tx.
	t.AppendStorageDiff(StorageDiff{uid: -size})
	return nil
}

// AppendStorageDiff appends the given storage diff to the transaction.
func (t *Tx) AppendStorageDiff(diff StorageDiff) {
	root := t
	for root.inherited {
		root = root.parent
	}

	if root.storageDiff == nil {
		root.storageDiff = diff
	} else {
		root.storageDiff.Merge(diff)
	}
}

// WithTx wraps the given inventory client with a transaction.
func WithTx[T TxOperator](ctx context.Context, c T) (T, *Tx, context.Context, error) {
	return WithTxOptions(ctx, c, nil)
}

// WithTxOptions applies native Ent options when starting a transaction.
// An inherited transaction retains its caller's isolation and ownership.
func WithTxOptions[T TxOperator](ctx context.Context, c T, opts *sql.TxOptions) (T, *Tx, context.Context, error) {
	var txClient *ent.Client
	var txWrapper *Tx

	if txInherited, ok := ctx.Value(TxCtx{}).(*Tx); ok && !txInherited.finished {
		txWrapper = &Tx{inherited: true, tx: txInherited.tx, parent: txInherited}
	} else {
		var tx *ent.Tx
		var err error
		if opts == nil {
			tx, err = c.GetClient().Tx(ctx)
		} else {
			tx, err = c.GetClient().BeginTx(ctx, opts)
		}
		if err != nil {
			return c, nil, ctx, fmt.Errorf("failed to create transaction: %w", err)
		}

		txWrapper = &Tx{inherited: false, tx: tx, baseClient: c.GetClient()}
		ctx = context.WithValue(ctx, TxCtx{}, txWrapper)
	}

	txClient = txWrapper.tx.Client()
	return c.SetClient(txClient).(T), txWrapper, ctx, nil
}

// InheritTx wraps the given inventory client with a transaction.
// If the transaction is already in the context, it will be inherited.
// Otherwise, original client will be returned.
func InheritTx[T TxOperator](ctx context.Context, c T) (T, *Tx) {
	var txClient *ent.Client
	var txWrapper *Tx

	if txInherited, ok := ctx.Value(TxCtx{}).(*Tx); ok && !txInherited.finished {
		txWrapper = &Tx{inherited: true, tx: txInherited.tx, parent: txInherited}
		txClient = txWrapper.tx.Client()
		return c.SetClient(txClient).(T), txWrapper
	}

	return c, nil
}

func Rollback(tx *Tx) error {
	if !tx.inherited {
		tx.finished = true
		tx.afterCommit = nil
		return tx.tx.Rollback()
	}

	return nil
}

// CommittedMetadataClient supplies nonlocking committed metadata independently
// of the accepting transaction pool. Authorization stays in that transaction.
// Callers must not borrow another connection for SQLite.
func CommittedMetadataClient(ctx context.Context) *ent.Client {
	if tx, ok := ctx.Value(TxCtx{}).(*Tx); ok && !tx.finished {
		for tx.parent != nil {
			tx = tx.parent
		}
		if metadata, ok := metadataClients.Load(tx.baseClient); ok {
			return metadata.(*ent.Client)
		}
		return tx.baseClient
	}
	return nil
}

func commit(tx *Tx) (bool, error) {
	if !tx.inherited {
		tx.finished = true
		err := tx.tx.Commit()
		tx.committed = err == nil
		callbacks := tx.afterCommit
		tx.afterCommit = nil
		if err == nil {
			for _, apply := range callbacks {
				apply()
			}
		}
		return true, err
	}
	return false, nil
}

// AfterCommit publishes observations only after the outermost write commits.
// Inherited filesystem operations must not expose uncommitted events or query
// their own pending writes through another database connection.
func AfterCommit(ctx context.Context, apply func()) {
	tx, _ := ctx.Value(TxCtx{}).(*Tx)
	if tx == nil {
		apply()
		return
	}
	for tx.inherited {
		tx = tx.parent
	}
	if !tx.finished {
		tx.afterCommit = append(tx.afterCommit, apply)
	} else if tx.committed {
		apply()
	}
}

func Commit(tx *Tx) error {
	_, err := commit(tx)
	return err
}

// CommitWithStorageDiff commits the transaction and applies the accumulated
// storage diff. Only the outermost (non-inherited) transaction performs the
// commit and the storage mutation.
//
// Quota enforcement is done UPFRONT via Tx.ReserveStorage, not here. This
// function's role is to (a) commit the tx, and (b) apply any residual
// storage diff produced by CreateEntity / CapEntities / etc. Tx.ReserveStorage
// pre-emits a matching negative diff, so pre-reserved sizes are netted out
// against the positive diff CreateEntity appends later. Residual is applied
// AFTER commit via ApplyStorageDiff (auto-commit, safe to retry on
// deadlock).
func CommitWithStorageDiff(ctx context.Context, tx *Tx, l logging.Logger, uc UserClient) error {
	committed, err := commit(tx)
	if err != nil {
		return err
	}

	if !committed {
		return nil
	}

	if err := uc.ApplyStorageDiff(ctx, tx.storageDiff); err != nil {
		l.Error("Failed to apply storage diff", "error", err)
	}

	return nil
}
